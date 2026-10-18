// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor metadata only. No native call, environment lookup or path
// opening belongs here; the parent's held native identity supplies the folder.
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"DCENV1\r\n";
const MAX_UNITS: usize = 2048;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExpectedEnvironment {
    pub(super) local_app_data: PathBuf,
    pub(super) temporary: PathBuf,
    pub(super) temporary_alias: PathBuf,
}

fn refused() -> io::Error {
    io::Error::other("native private environment binding refused")
}

fn disk_units(value: &OsStr) -> io::Result<Vec<u16>> {
    let raw: Vec<_> = value.encode_wide().take(MAX_UNITS + 1).collect();
    if raw.len() > MAX_UNITS || raw.contains(&0) {
        return Err(refused());
    }
    let value = raw.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&raw);
    if value.len() < 4
        || !((65..=90).contains(&value[0]) || (97..=122).contains(&value[0]))
        || value[1..3] != [58, 92]
    {
        return Err(refused());
    }
    for component in value[3..].split(|unit| *unit == 92) {
        if component.is_empty()
            || component == [46]
            || component == [46, 46]
            || component.last().is_some_and(|unit| [32, 46].contains(unit))
            || component
                .iter()
                .any(|unit| *unit < 32 || [47, 58].contains(unit))
        {
            return Err(refused());
        }
    }
    Ok(value.to_vec())
}

fn profile_component(remainder: &[u16]) -> io::Result<&[u16]> {
    let parts: Vec<_> = remainder.split(|unit| *unit == 92).collect();
    if parts.len() != 2
        || parts[1] != [65, 67]
        || parts[0].is_empty()
        || parts[0].len() > 128
        || !parts[0].iter().all(|unit| {
            (48..=57).contains(unit)
                || (65..=90).contains(unit)
                || (97..=122).contains(unit)
                || [45, 46, 95].contains(unit)
        })
    {
        return Err(io::Error::other("native profile component shape refused"));
    }
    Ok(parts[0])
}

impl ExpectedEnvironment {
    // GetAppContainerFolderPath binds the same-child SID to the CALLER's user
    // profile. Require that exact trusted known-folder base; carry only its
    // one validated profile component into the already held fresh fixture.
    // Neither source path is opened here or accepted from a child environment.
    pub(super) fn from_caller_profile(
        root: &Path,
        caller_local_app_data: &OsStr,
        native_folder: &OsStr,
    ) -> io::Result<Self> {
        let mut prefix = disk_units(caller_local_app_data)?;
        prefix.extend(r"\Packages\".encode_utf16());
        let native = disk_units(native_folder)?;
        let remainder = native
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| io::Error::other("native profile caller known-folder base differs"))?;
        let profile = profile_component(remainder)?;
        let mapped = root
            .join(r"home\AppData\Local\Packages")
            .join(OsString::from_wide(profile))
            .join("AC");
        Self::from_native_folder(root, mapped.as_os_str())
    }

    pub(super) fn from_native_folder(root: &Path, folder: &OsStr) -> io::Result<Self> {
        let mut prefix = disk_units(root.as_os_str())?;
        prefix.extend(r"\home\AppData\Local\Packages\".encode_utf16());
        let value = disk_units(folder)?;
        let remainder = value.strip_prefix(prefix.as_slice()).ok_or_else(refused)?;
        profile_component(remainder)?;
        let local_app_data = PathBuf::from(folder);
        let temporary = local_app_data.join("Temp");
        disk_units(temporary.as_os_str())?;
        Ok(Self {
            local_app_data,
            temporary_alias: temporary.clone(),
            temporary,
        })
    }

    pub(super) fn write_to(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_all(MAGIC)?;
        for path in [&self.local_app_data, &self.temporary, &self.temporary_alias] {
            let units: Vec<_> = path.as_os_str().encode_wide().take(MAX_UNITS + 1).collect();
            if units.is_empty() || units.len() > MAX_UNITS || units.contains(&0) {
                return Err(refused());
            }
            writer.write_all(&(units.len() as u32).to_le_bytes())?;
            for unit in units {
                writer.write_all(&unit.to_le_bytes())?;
            }
        }
        writer.flush()
    }

    pub(super) fn read_from(mut reader: impl Read, root: &Path) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(refused());
        }
        let mut paths = Vec::with_capacity(3);
        for _ in 0..3 {
            let mut count = [0; 4];
            reader.read_exact(&mut count)?;
            let count = u32::from_le_bytes(count) as usize;
            if count == 0 || count > MAX_UNITS {
                return Err(refused());
            }
            let mut units = Vec::with_capacity(count);
            for _ in 0..count {
                let mut unit = [0; 2];
                reader.read_exact(&mut unit)?;
                units.push(u16::from_le_bytes(unit));
            }
            if units.contains(&0) {
                return Err(refused());
            }
            paths.push(PathBuf::from(OsString::from_wide(&units)));
        }
        let expected = Self::from_native_folder(root, paths[0].as_os_str())?;
        if paths[1].as_os_str() != expected.temporary.as_os_str()
            || paths[2].as_os_str() != expected.temporary_alias.as_os_str()
        {
            return Err(refused());
        }
        let mut trailing = [0];
        if reader.read(&mut trailing)? != 0 {
            return Err(refused());
        }
        Ok(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_folder_requires_exact_private_branch_and_one_profile_component() {
        let root = Path::new(r"C:\fixed-private\dc-axis-windows-psec-fixed");
        for folder in [
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\native-profile_1\AC",
            r"\\?\C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\native-profile_1\AC",
        ] {
            assert!(ExpectedEnvironment::from_native_folder(root, OsStr::new(folder)).is_ok());
        }
        for folder in [
            r"C:\Users\real-user\AppData\Local\Packages\profile\AC",
            r"D:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed-other\home\AppData\Local\Packages\profile\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\extra\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\..\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile.\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile:ads\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\LocalCache",
            r"\\server\share\home\AppData\Local\Packages\profile\AC",
        ] {
            assert!(ExpectedEnvironment::from_native_folder(root, OsStr::new(folder)).is_err());
        }
        // Same native profile authority, different caller/private user roots.
        // Only the SID-derived component transfers; host paths never do.
        let caller = OsStr::new(r"C:\Users\fixed-caller\AppData\Local");
        let native =
            OsStr::new(r"C:\Users\fixed-caller\AppData\Local\Packages\native-profile_1\AC");
        let mapped = ExpectedEnvironment::from_caller_profile(root, caller, native).unwrap();
        assert_eq!(
            mapped.local_app_data,
            root.join(r"home\AppData\Local\Packages\native-profile_1\AC")
        );
        assert_eq!(mapped.temporary, mapped.local_app_data.join("Temp"));
        assert_eq!(mapped.temporary_alias, mapped.temporary);
        // A different mounted caller base is permissible only when BOTH
        // independently queried native values match it exactly.
        let unicode_base = OsStr::new(r"\\?\D:\fixed-λ-雪\local");
        let unicode_native = OsStr::new(r"D:\fixed-λ-雪\local\Packages\native-profile_1\AC");
        assert_eq!(
            ExpectedEnvironment::from_caller_profile(root, unicode_base, unicode_native).unwrap(),
            mapped
        );
        for candidate in [
            r"C:\Users\other-caller\AppData\Local\Packages\native-profile_1\AC",
            r"C:\Users\fixed-caller\AppData\Local-extra\Packages\native-profile_1\AC",
            r"C:\Users\fixed-caller\AppData\Local\Packages\native-profile_1\extra\AC",
            r"C:\Users\fixed-caller\AppData\Local\Packages\native-profile_1\LocalCache",
            r"C:\Users\fixed-caller\AppData\Local\Packages\..\AC",
            r"C:\Users\fixed-caller\AppData\Local\Packages\native:ads\AC",
            r"C:\Users\fixed-caller\AppData\Local\Packages\native-profile.\AC",
            r"C:\Users\fixed-caller\AppData\Local\Packages\λ-雪\AC",
            r"\\server\share\Packages\native-profile_1\AC",
        ] {
            assert!(
                ExpectedEnvironment::from_caller_profile(root, caller, OsStr::new(candidate))
                    .is_err()
            );
        }
        assert!(
            ExpectedEnvironment::from_caller_profile(Path::new(r"\\server\share"), caller, native)
                .is_err()
        );
        assert!(
            ExpectedEnvironment::from_caller_profile(
                root,
                OsStr::new(r"C:\Users\fixed-caller\AppData\Local\.."),
                native
            )
            .is_err()
        );
        let oversize_profile = format!(
            r"C:\Users\fixed-caller\AppData\Local\Packages\{}\AC",
            "x".repeat(129)
        );
        assert!(
            ExpectedEnvironment::from_caller_profile(root, caller, OsStr::new(&oversize_profile))
                .is_err()
        );
        let mut frame = Vec::new();
        mapped.write_to(&mut frame).unwrap();
        assert_eq!(
            ExpectedEnvironment::read_from(frame.as_slice(), root).unwrap(),
            mapped
        );
    }

    #[test]
    fn native_environment_utf16_frame_roundtrips_and_refuses_tampering() {
        let root = Path::new(r"\\?\C:\fixed-λ-雪\dc-axis-windows-psec-fixed");
        let folder = root.join(r"home\AppData\Local\Packages\native-profile\AC");
        let value = ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).unwrap();
        let mut bytes = Vec::new();
        value.write_to(&mut bytes).unwrap();
        assert_eq!(
            ExpectedEnvironment::read_from(bytes.as_slice(), root).unwrap(),
            value
        );
        for size in [0, 7, bytes.len() - 1] {
            assert!(ExpectedEnvironment::read_from(&bytes[..size], root).is_err());
        }
        let mut oversized = bytes.clone();
        oversized[8..12].copy_from_slice(&((MAX_UNITS + 1) as u32).to_le_bytes());
        assert!(ExpectedEnvironment::read_from(oversized.as_slice(), root).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ExpectedEnvironment::read_from(trailing.as_slice(), root).is_err());
        let mut nul = bytes.clone();
        nul[12..14].fill(0);
        assert!(ExpectedEnvironment::read_from(nul.as_slice(), root).is_err());
        let mut mismatch =
            ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).unwrap();
        mismatch.temporary_alias = root.join("tmp");
        let mut bytes = Vec::new();
        mismatch.write_to(&mut bytes).unwrap();
        assert!(ExpectedEnvironment::read_from(bytes.as_slice(), root).is_err());
    }
}
