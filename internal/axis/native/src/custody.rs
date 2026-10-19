// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Linux capability handoff. Guest path labels are never reopened on the host.
//!
//! The trusted factory supplies fd3=namespace proof (consumed before control),
//! fd4=bwrap image, fd5=payload image, fd6=cwd, then read/write objects. Deny masks and
//! overlapping destinations refuse until a qualified translation exists.
//! Images are immutable sealed memfds made from the host-admitted bytes. The
//! full authority, original image digests and resolver records stay in Go.

use crate::wire::{HOOK_DIRECTORY, Preparation, ProtocolError, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};

const FIRST_CAP: i32 = 4;
const IMAGE_BOUND: u64 = 512 << 20;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
    pub directory: bool,
}

pub struct HeldObject {
    file: File,
    identity: ObjectIdentity,
}

impl HeldObject {
    fn new(file: File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| ProtocolError)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(ProtocolError);
        }
        Ok(Self {
            identity: ObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                directory: metadata.is_dir(),
            },
            file,
        })
    }

    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn into_file(self) -> File {
        self.file
    }
}

pub struct SealedImage(HeldObject);

impl SealedImage {
    fn new(file: File) -> Result<Self> {
        let object = HeldObject::new(file)?;
        let metadata = object.file.metadata().map_err(|_| ProtocolError)?;
        // SAFETY: F_GET_SEALS only queries this owned descriptor.
        let seals = unsafe { libc::fcntl(object.file.as_raw_fd(), libc::F_GET_SEALS) };
        let mut header = [0; 20];
        if metadata.is_dir()
            || metadata.len() < 20
            || metadata.len() > IMAGE_BOUND
            || metadata.mode() & 0o6000 != 0
            || seals < 0
            || seals & SEALS != SEALS
            || object
                .file
                .read_at(&mut header, 0)
                .map_err(|_| ProtocolError)?
                != header.len()
            || &header[..6] != b"\x7fELF\x02\x01"
            || u16::from_le_bytes([header[18], header[19]]) != 62
        {
            return Err(ProtocolError);
        }
        Ok(Self(object))
    }

    pub fn file(&self) -> &File {
        self.0.file()
    }
    pub fn into_file(self) -> File {
        self.0.into_file()
    }
}

pub struct PreparedFiles {
    pub bwrap: SealedImage,
    pub payload: SealedImage,
    pub cwd: HeldObject,
    pub read: Vec<HeldObject>,
    pub write: Vec<HeldObject>,
    pub hook_pins: Option<HookPins>,
}

// Retained through the native process lifetime. The directory mount itself is
// a separate held read grant; these pins only verify its two fixed children.
pub struct HookPins {
    pub socket: File,
    pub profile: File,
}

impl PreparedFiles {
    /// Transfer the factory's explicit child-owned capability table once.
    /// No native library, worker or backend may open descriptors before this.
    pub fn receive(plan: &Preparation) -> Result<Self> {
        let count = Self::count(plan)?;
        let mut files = Vec::with_capacity(count);
        for offset in 0..count {
            let descriptor = FIRST_CAP + i32::try_from(offset).map_err(|_| ProtocolError)?;
            // SAFETY: the private factory contract transfers precisely these
            // descriptors to this one-session child. A failed query owns none.
            if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
                return Err(ProtocolError);
            }
            let file = unsafe { File::from_raw_fd(descriptor) };
            // Never leak a preparation capability through an unrelated exec.
            // The reviewed backend duplicates only its explicit mount inputs.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(ProtocolError);
            }
            files.push(file);
        }
        Self::from_files(plan, files)
    }

    fn count(plan: &Preparation) -> Result<usize> {
        plan.validate()?;
        if plan.backend != "bubblewrap"
            || plan.terminal.is_some()
            || !plan.filesystem.deny.is_empty()
            || plan.argv[0] != "/.defenseclaw/payload"
        {
            return Err(ProtocolError);
        }
        let paths: Vec<_> = plan
            .filesystem
            .read
            .iter()
            .chain(&plan.filesystem.write)
            .collect();
        for (index, path) in paths.iter().enumerate() {
            let hook_grant = plan.hook.as_ref().is_some_and(|hook| {
                index == usize::from(hook.read_index) && *path == HOOK_DIRECTORY
            });
            if !normalized(path)
                || ["/proc", "/dev", "/.defenseclaw", HOOK_DIRECTORY]
                    .iter()
                    .any(|root| covers(path, root) || covers(root, path))
                    && !hook_grant
            {
                return Err(ProtocolError);
            }
            if paths[index + 1..]
                .iter()
                .any(|other| covers(path, other) || covers(other, path))
            {
                return Err(ProtocolError);
            }
        }
        Ok(3 + plan.filesystem.read.len() + plan.filesystem.write.len())
    }

    pub fn from_files(plan: &Preparation, files: Vec<File>) -> Result<Self> {
        if files.len() != Self::count(plan)? {
            return Err(ProtocolError);
        }
        let mut files = files.into_iter();
        let mut next = || files.next().ok_or(ProtocolError);
        let bwrap = SealedImage::new(next()?)?;
        let payload = SealedImage::new(next()?)?;
        let cwd = HeldObject::new(next()?)?;
        if !cwd.identity.directory {
            return Err(ProtocolError);
        }
        let mut objects = |count| -> Result<Vec<HeldObject>> {
            (0..count).map(|_| HeldObject::new(next()?)).collect()
        };
        let read = objects(plan.filesystem.read.len())?;
        let write = objects(plan.filesystem.write.len())?;
        let hook_pins = match &plan.hook {
            None => None,
            Some(hook) => Some(verify_hook_directory(
                read.get(usize::from(hook.read_index))
                    .ok_or(ProtocolError)?,
                &hook.profile_digest,
                &hook.session_id,
            )?),
        };
        // The initial peer admits only an exact cwd grant. More complex guest
        // mappings need their own object-relative native admission first.
        let granted_cwd = plan
            .filesystem
            .read
            .iter()
            .zip(&read)
            .chain(plan.filesystem.write.iter().zip(&write))
            .any(|(destination, object)| {
                destination == &plan.workdir && object.identity == cwd.identity
            });
        if !granted_cwd {
            return Err(ProtocolError);
        }
        Ok(Self {
            bwrap,
            payload,
            cwd,
            read,
            write,
            hook_pins,
        })
    }
}

fn held_child(parent: &File, name: &std::ffi::CStr, flags: i32) -> Result<File> {
    // SAFETY: lookup is relative to the already received directory capability.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(ProtocolError);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn exact_hook_entries(parent: &HeldObject) -> Result<()> {
    let directory = held_child(parent.file(), c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let opened = directory.metadata().map_err(|_| ProtocolError)?;
    let held = parent.file.metadata().map_err(|_| ProtocolError)?;
    if opened.dev() != held.dev() || opened.ino() != held.ino() {
        return Err(ProtocolError);
    }
    let mut seen_socket = false;
    let mut seen_profile = false;
    let mut bytes = [0u8; 4096];
    for _ in 0..5 {
        // SAFETY: getdents64 writes at most the stack buffer size to the
        // independent, held directory descriptor; records are checked below.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        if count < 0 || usize::try_from(count).map_err(|_| ProtocolError)? > bytes.len() {
            return Err(ProtocolError);
        }
        if count == 0 {
            return if seen_socket && seen_profile {
                Ok(())
            } else {
                Err(ProtocolError)
            };
        }
        let count = usize::try_from(count).map_err(|_| ProtocolError)?;
        let mut offset = 0;
        while offset < count {
            if count - offset < 20 {
                return Err(ProtocolError);
            }
            let record = &bytes[offset..count];
            let size = usize::from(u16::from_ne_bytes([record[16], record[17]]));
            if size < 20 || size > record.len() {
                return Err(ProtocolError);
            }
            let name = &record[19..size];
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(ProtocolError)?;
            match &name[..end] {
                b"." | b".." => {}
                b"ingress.sock" if !seen_socket => seen_socket = true,
                b"runtime.json" if !seen_profile => seen_profile = true,
                _ => return Err(ProtocolError),
            }
            offset += size;
        }
    }
    Err(ProtocolError)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookProfile {
    version: u8,
    session_id: String,
    connector: String,
    hook_contract: String,
    hook_surface: String,
}

fn verify_hook_directory(
    parent: &HeldObject,
    profile_digest: &str,
    session_id: &str,
) -> Result<HookPins> {
    let directory = parent.file();
    let before = directory.metadata().map_err(|_| ProtocolError)?;
    if !before.is_dir()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o7777 != 0o700
    {
        return Err(ProtocolError);
    }
    exact_hook_entries(parent)?;
    let socket = held_child(directory, c"ingress.sock", libc::O_PATH)?;
    let socket_meta = socket.metadata().map_err(|_| ProtocolError)?;
    if !socket_meta.file_type().is_socket()
        || socket_meta.uid() != before.uid()
        || socket_meta.nlink() != 1
        || socket_meta.mode() & 0o7777 != 0o600
    {
        return Err(ProtocolError);
    }
    // O_NONBLOCK prevents a substituted FIFO from stalling admission before
    // its metadata is checked and refused below.
    let profile = held_child(
        directory,
        c"runtime.json",
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    let profile_meta = profile.metadata().map_err(|_| ProtocolError)?;
    if !profile_meta.is_file()
        || profile_meta.uid() != before.uid()
        || profile_meta.nlink() != 1
        || profile_meta.mode() & 0o7777 != 0o400
        || profile_meta.len() == 0
        || profile_meta.len() > 4096
    {
        return Err(ProtocolError);
    }
    let mut bytes = vec![0u8; usize::try_from(profile_meta.len()).map_err(|_| ProtocolError)?];
    profile
        .read_exact_at(&mut bytes, 0)
        .map_err(|_| ProtocolError)?;
    let after = directory.metadata().map_err(|_| ProtocolError)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || profile.metadata().map_err(|_| ProtocolError)?.len() != profile_meta.len()
    {
        return Err(ProtocolError);
    }
    let mut actual = String::from("sha256:");
    for byte in Sha256::digest(&bytes) {
        use std::fmt::Write;
        write!(&mut actual, "{byte:02x}").map_err(|_| ProtocolError)?;
    }
    if actual != profile_digest {
        return Err(ProtocolError);
    }
    // The digest binds exact bytes, while this check binds those bytes to the
    // one authenticated Prepare session. It never derives bearer authority.
    let parsed: HookProfile = serde_json::from_slice(&bytes).map_err(|_| ProtocolError)?;
    if parsed.version != 1
        || parsed.session_id != session_id
        || parsed.connector.is_empty()
        || parsed.hook_contract.is_empty()
        || parsed.connector.len() > 128
        || parsed.hook_contract.len() > 128
        || parsed.hook_surface.len() > 128
    {
        return Err(ProtocolError);
    }
    Ok(HookPins { socket, profile })
}

fn normalized(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn covers(path: &str, other: &str) -> bool {
    other == path
        || path == "/" && other.starts_with('/')
        || other
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Filesystem, Variable};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn image(sealed: bool) -> File {
        // Synthetic ELF header only. It is never executed by these tests.
        let fd = unsafe {
            libc::memfd_create(
                c"fixed-inert-native-image".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0);
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut bytes = [0; 20];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18] = 62;
        file.write_all(&bytes).unwrap();
        if sealed {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) }, 0);
        }
        file
    }

    fn plan() -> Preparation {
        Preparation {
            backend: "bubblewrap".into(),
            argv: vec!["/.defenseclaw/payload".into()],
            environment: vec![Variable {
                name: "HOME".into(),
                value: "/guest/work".into(),
            }],
            workdir: "/guest/work".into(),
            filesystem: Filesystem {
                read: vec![],
                write: vec!["/guest/work".into()],
                deny: vec![],
            },
            offline: true,
            terminal: None,
            timeout_ms: 1000,
            output_limit: 1024,
            hook: None,
        }
    }

    #[test]
    fn prepared_capabilities_survive_host_name_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::create_dir(&original).unwrap();
        let directory = File::open(&original).unwrap();
        let caps = vec![
            image(true),
            image(true),
            directory.try_clone().unwrap(),
            directory,
        ];
        let prepared = PreparedFiles::from_files(&plan(), caps).unwrap();
        let identity = prepared.cwd.identity();
        std::fs::rename(&original, root.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        assert_eq!(
            prepared.cwd.file().metadata().unwrap().ino(),
            identity.inode
        );
        assert_ne!(
            File::open(original).unwrap().metadata().unwrap().ino(),
            identity.inode
        );
    }

    #[test]
    fn mutable_image_and_mismatched_cwd_objects_refuse() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let caps = vec![
            image(false),
            image(true),
            directory.try_clone().unwrap(),
            directory,
        ];
        assert!(PreparedFiles::from_files(&plan(), caps).is_err());
        let other = tempfile::tempdir().unwrap();
        let caps = vec![
            image(true),
            image(true),
            File::open(root.path()).unwrap(),
            File::open(other.path()).unwrap(),
        ];
        assert!(PreparedFiles::from_files(&plan(), caps).is_err());
    }

    #[test]
    fn untranslated_masks_overlaps_and_backends_refuse_before_capability_transfer() {
        let original = plan();
        for field in [
            "deny",
            "overlap",
            "synthetic",
            "root",
            "backend",
            "terminal",
            "payload",
        ] {
            let mut plan = original.clone();
            match field {
                "deny" => plan.filesystem.deny.push("/guest/work/secret".into()),
                "overlap" => plan.filesystem.read.push("/guest/work/nested".into()),
                "synthetic" => plan.filesystem.read.push("/proc/1".into()),
                "root" => plan.filesystem.read.push("/".into()),
                "backend" => plan.backend = "seatbelt".into(),
                "terminal" => {
                    plan.terminal = Some(crate::wire::Size {
                        rows: 24,
                        columns: 80,
                    })
                }
                "payload" => plan.argv[0] = "/unbound/agent".into(),
                _ => unreachable!(),
            }
            assert!(PreparedFiles::count(&plan).is_err(), "{field}");
        }
        assert!(PreparedFiles::count(&original).is_ok());
    }

    #[test]
    fn typed_hook_grant_requires_exact_private_two_entry_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = root.path().join("runtime.json");
        let bytes = br#"{"version":1,"session_id":"fixed","connector":"claudecode","hook_contract":"command","hook_surface":""}"#;
        std::fs::write(&profile, bytes).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o400)).unwrap();
        let socket = root.path().join("ingress.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut digest = String::from("sha256:");
        for byte in Sha256::digest(bytes) {
            use std::fmt::Write;
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        let held = HeldObject::new(File::open(root.path()).unwrap()).unwrap();
        let pins = verify_hook_directory(&held, &digest, "fixed").unwrap();
        assert!(pins.socket.metadata().unwrap().file_type().is_socket());
        assert_eq!(pins.profile.metadata().unwrap().len(), bytes.len() as u64);
        assert!(verify_hook_directory(&held, &digest, "other").is_err());
        assert!(
            verify_hook_directory(&held, &format!("sha256:{}", "0".repeat(64)), "fixed").is_err()
        );
        std::fs::write(root.path().join("extra"), b"unexpected").unwrap();
        assert!(verify_hook_directory(&held, &digest, "fixed").is_err());
        drop(listener);
    }

    #[test]
    fn hook_profile_schema_refuses_duplicate_unknown_and_missing_fields() {
        for raw in [
            br#"{"version":1,"session_id":"fixed","session_id":"other","connector":"claudecode","hook_contract":"command","hook_surface":""}"#.as_slice(),
            br#"{"version":1,"session_id":"fixed","connector":"claudecode","hook_contract":"command","hook_surface":"","bearer":"secret"}"#.as_slice(),
            br#"{"version":1,"session_id":"fixed","connector":"claudecode","hook_contract":"command"}"#.as_slice(),
            br#"{"version":1,"session_id":null,"connector":"claudecode","hook_contract":"command","hook_surface":""}"#.as_slice(),
            br#"{"version":1,"session_id":"fixed","connector":"claudecode","hook_contract":"command","hook_surface":""}{}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<HookProfile>(raw).is_err());
        }
    }
}
