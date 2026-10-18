// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Parent-only, read/query operations. No profile/namespace creation, token
// adjustment, impersonation, ACL mutation or child environment lookup.
use super::native_environment::{
    ExpectedEnvironment, StartupEnvironment, classify_profile_refusal,
};
use anyhow::{Context, Result, ensure};
use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::NtOpenFile;
use windows::Win32::Foundation::{
    ERROR_NO_TOKEN, HANDLE, HLOCAL, LocalFree, OBJECT_ATTRIBUTE_FLAGS, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::GetAppContainerFolderPath;
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, PSID, TOKEN_QUERY, TokenAppContainerSid,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FileAttributeTagInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
    QueryDosDeviceW,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::{GetCurrentThread, OpenProcessToken, OpenThreadToken};
use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};

#[link(name = "shell32")]
unsafe extern "system" {
    #[link_name = "SHGetKnownFolderPath"]
    fn known_folder_path(
        identifier: *const GUID,
        flags: u32,
        token: HANDLE,
        result: *mut PWSTR,
    ) -> HRESULT;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "CompareStringOrdinal"]
    fn compare_string_ordinal(
        first: *const u16,
        first_count: i32,
        second: *const u16,
        second_count: i32,
        ignore_case: i32,
    ) -> i32;
}

fn ordinal_equal(first: &[u16], second: &[u16]) -> Option<bool> {
    // Diagnostic only, never used by admission. Fixed explicit lengths avoid
    // native NUL scanning; zero/unknown native return remains unknown.
    if first.is_empty() || second.is_empty() || first.len() > 2060 || second.len() > 2060 {
        return None;
    }
    match unsafe {
        compare_string_ordinal(
            first.as_ptr(),
            first.len() as i32,
            second.as_ptr(),
            second.len() as i32,
            1,
        )
    } {
        1 | 3 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtOpenSymbolicLinkObject"]
    fn open_symbolic_link(
        result: *mut HANDLE,
        access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
    ) -> i32;
    #[link_name = "NtQuerySymbolicLinkObject"]
    fn query_symbolic_link(handle: HANDLE, target: *mut UNICODE_STRING, returned: *mut u32) -> i32;
}

pub(super) struct NativeEnvironmentCustody {
    pub(super) expected: ExpectedEnvironment,
    _directories: Vec<OwnedHandle>,
}

pub(super) struct FixtureCustody {
    directories: Vec<OwnedHandle>,
    drive: u16,
    volume: Vec<u16>,
    root_units: Vec<u16>,
}

pub(super) struct CallerEnvironment {
    startup: StartupEnvironment,
    local_app_data: OsString,
}

impl CallerEnvironment {
    pub(super) fn capture(system: &Path) -> Result<Self> {
        let startup = StartupEnvironment::from_startup_entries(
            std::env::vars_os(),
            system,
            &std::env::current_dir()?,
        )
        .context("original private startup environment shape refused")?;
        // Freeze before fixture setup, SDK calls or worker threads. Both native
        // folder queries later run under these same original eight path values.
        startup.require_unchanged(std::env::vars_os(), false)?;
        let local_app_data = caller_local_app_data()?;
        startup.require_unchanged(std::env::vars_os(), false)?;
        Ok(Self {
            startup,
            local_app_data,
        })
    }

    pub(super) fn require_unchanged(&self) -> Result<()> {
        self.startup.require_unchanged(std::env::vars_os(), true)?;
        Ok(())
    }
}

fn owned(handle: HANDLE) -> Result<OwnedHandle> {
    ensure!(
        !handle.is_invalid() && handle != HANDLE::default(),
        "native query returned no handle"
    );
    // SAFETY: callers pass only a newly created handle after successful API return.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

fn handle(file: &OwnedHandle) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

unsafe fn bounded_wide(pointer: PWSTR, maximum: usize) -> Result<Vec<u16>> {
    ensure!(!pointer.is_null(), "native string result is absent");
    // These OS APIs promise a NUL-terminated allocated result. The fixed cap
    // bounds iteration; the allocation stays alive until its matching free.
    for index in 0..=maximum {
        if unsafe { *pointer.0.add(index) } == 0 {
            ensure!(index != 0, "native string result is empty");
            return Ok(unsafe { std::slice::from_raw_parts(pointer.0, index) }.to_vec());
        }
    }
    anyhow::bail!("native string result exceeds fixed bound")
}

// Validate every SID byte range before handing a returned in-buffer pointer to
// IsValidSid/GetLengthSid. Null, forged offsets/counts and unknown shape refuse.
fn sid_range(bytes: &[u8], address: usize) -> Result<std::ops::Range<usize>> {
    let start = bytes.as_ptr() as usize;
    let offset = address
        .checked_sub(start)
        .ok_or_else(|| anyhow::anyhow!("native SID pointer is outside result"))?;
    ensure!(
        offset >= size_of::<usize>() && offset <= bytes.len().saturating_sub(8),
        "native SID header is outside result"
    );
    ensure!(
        bytes[offset] == 1 && bytes[offset + 1] <= 15,
        "native SID shape differs"
    );
    let end = offset
        .checked_add(8 + 4 * usize::from(bytes[offset + 1]))
        .ok_or_else(|| anyhow::anyhow!("native SID length overflow"))?;
    ensure!(end <= bytes.len(), "native SID body is outside result");
    Ok(offset..end)
}

fn require_process_identity_context() -> Result<()> {
    let mut token = HANDLE::default();
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Ok(()) => {
            let _token = owned(token)?;
            anyhow::bail!("native folder query thread has an unexpected token");
        }
        Err(error) => ensure!(
            error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0),
            "native folder query thread identity is unknown"
        ),
    }
    Ok(())
}

fn caller_local_app_data() -> Result<OsString> {
    require_process_identity_context()?;
    // Knownfolders.h FOLDERID_LocalAppData. Query only: DONT_VERIFY avoids
    // opening/verifying a host profile directory; NO_PACKAGE_REDIRECTION gets
    // the caller's unredirected base. No CREATE, INIT, default-path assumption,
    // environment-derived base, thread impersonation or filesystem fallback.
    const LOCAL_APP_DATA: GUID = GUID::from_u128(0xf1b32785_6fba_4fcf_9d55_7b8e7f157091);
    const QUERY_FLAGS: u32 = 0x0000_4000 | 0x0001_0000;
    let mut result = PWSTR::null();
    let status =
        unsafe { known_folder_path(&LOCAL_APP_DATA, QUERY_FLAGS, HANDLE::default(), &mut result) };
    let units = if status.is_ok() {
        unsafe { bounded_wide(result, 2048) }
    } else {
        Err(anyhow::anyhow!("caller native known-folder query refused"))
    };
    // The API requires freeing a nonnull out-pointer even on failure. Use the
    // exact native ABI rather than losing that pointer in Result<PWSTR>.
    if !result.is_null() {
        unsafe { CoTaskMemFree(Some(result.0.cast())) };
    }
    require_process_identity_context()?;
    Ok(OsString::from_wide(&units?))
}

fn native_folder(process: &OwnedHandle) -> Result<OsString> {
    require_process_identity_context()?;
    let mut raw_token = HANDLE::default();
    unsafe { OpenProcessToken(handle(process), TOKEN_QUERY, &mut raw_token) }
        .map_err(|_| anyhow::anyhow!("same-child token query refused"))?;
    let token = owned(raw_token)?;
    let mut words = [0u64; 512]; // aligned, fixed 4096-byte result; no allocation from OS length
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            handle(&token),
            TokenAppContainerSid,
            Some(words.as_mut_ptr().cast()),
            size_of::<[u64; 512]>() as u32,
            &mut returned,
        )
    }
    .map_err(|_| anyhow::anyhow!("same-child AppContainer SID unavailable"))?;
    ensure!(
        (size_of::<usize>()..=size_of::<[u64; 512]>()).contains(&(returned as usize)),
        "native SID query length differs"
    );
    let bytes =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), returned as usize) };
    let mut encoded_pointer = [0u8; size_of::<usize>()];
    encoded_pointer.copy_from_slice(&bytes[..size_of::<usize>()]);
    let address = usize::from_ne_bytes(encoded_pointer);
    let range = sid_range(bytes, address)?;
    let sid = PSID(address as *mut _);
    ensure!(
        unsafe { IsValidSid(sid) }.as_bool()
            && unsafe { GetLengthSid(sid) } as usize == range.len(),
        "native AppContainer SID validation refused"
    );
    let mut string = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut string) }
        .map_err(|_| anyhow::anyhow!("native SID string conversion refused"))?;
    // Free even when bounded conversion refuses. Never log this identity.
    let sid_units = unsafe { bounded_wide(string, 192) };
    let freed = unsafe { LocalFree(Some(HLOCAL(string.0.cast()))) };
    ensure!(freed.is_invalid(), "native SID string release failed");
    let mut sid_units = sid_units?;
    sid_units.push(0);
    let folder = unsafe { GetAppContainerFolderPath(PCWSTR(sid_units.as_ptr())) }
        .map_err(|_| anyhow::anyhow!("native AppContainer folder query refused"))?;
    let units = unsafe { bounded_wide(folder, 2048) };
    unsafe { CoTaskMemFree(Some(folder.0.cast())) };
    require_process_identity_context()?;
    Ok(OsString::from_wide(&units?))
}

fn unicode(value: &mut [u16]) -> Result<UNICODE_STRING> {
    ensure!(
        !value.is_empty() && value.len() <= 4096 && !value.contains(&0),
        "fixed native object name refused"
    );
    Ok(UNICODE_STRING {
        Length: (value.len() * 2) as u16,
        MaximumLength: (value.len() * 2) as u16,
        Buffer: PWSTR(value.as_mut_ptr()),
    })
}

fn attributes(root: HANDLE, name: &UNICODE_STRING, flags: u32) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: name,
        Attributes: OBJECT_ATTRIBUTE_FLAGS(flags),
        ..Default::default()
    }
}

fn open_directory(root: HANDLE, value: &mut [u16]) -> Result<OwnedHandle> {
    let name = unicode(value)?;
    let attrs = attributes(root, &name, 0x40 | 0x1000); // CASE_INSENSITIVE | DONT_REPARSE
    let mut result = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    // Open only: list + attributes + synchronize makes no-delete sharing an
    // effective directory-name pin. Share reads/writes to preserve normal
    // ancestor/content operations; directory contents and metadata are not
    // immutable. Refuse reparse points and never create a directory.
    ensure!(
        unsafe {
            NtOpenFile(
                &mut result,
                0x0010_0081,
                &attrs,
                &mut status,
                3,
                0x0020_0021,
            )
        }
        .0 >= 0,
        "private native directory open refused"
    );
    let result = owned(result)?;
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle(&result),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|_| anyhow::anyhow!("private native directory query refused"))?;
    ensure!(
        info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
            && info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "private native directory is redirected"
    );
    Ok(result)
}

fn effective_fixed_volume(drive: u16) -> Result<Vec<u16>> {
    let alias = [drive, 58, 0];
    let mut effective = [0u16; 1024];
    let count = unsafe { QueryDosDeviceW(PCWSTR(alias.as_ptr()), Some(&mut effective)) };
    ensure!(
        count > 0 && (count as usize) < effective.len(),
        "fixed drive query refused"
    );
    let effective = effective.split(|u| *u == 0).next().unwrap_or_default();
    let mut global: Vec<_> = r"\GLOBAL??\".encode_utf16().chain([drive, 58]).collect();
    let name = unicode(&mut global)?;
    let attrs = attributes(HANDLE::default(), &name, 0x40);
    let mut link = HANDLE::default();
    ensure!(
        unsafe { open_symbolic_link(&mut link, 1, &attrs) } >= 0,
        "global drive identity unavailable"
    );
    let link = owned(link)?;
    let mut target = [0u16; 1024];
    let mut output = UNICODE_STRING {
        Length: 0,
        MaximumLength: (target.len() * 2) as u16,
        Buffer: PWSTR(target.as_mut_ptr()),
    };
    let mut returned = 0;
    ensure!(
        unsafe { query_symbolic_link(handle(&link), &mut output, &mut returned) } >= 0
            && output.Length > 0
            && output.Length % 2 == 0
            && usize::from(output.Length) <= target.len() * 2,
        "global drive target query refused"
    );
    let global = &target[..usize::from(output.Length) / 2];
    ensure!(
        effective == global,
        "local drive alias differs from global mount"
    );
    let label = String::from_utf16(global)
        .map_err(|_| anyhow::anyhow!("fixed drive target encoding refused"))?;
    let suffix = label
        .strip_prefix(r"\Device\HarddiskVolume")
        .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| anyhow::anyhow!("mapped or redirected fixed drive refused"))?;
    Ok(format!(r"\Device\HarddiskVolume{suffix}\")
        .encode_utf16()
        .collect())
}

pub(super) fn pin_fixture_root(root: &Path) -> Result<FixtureCustody> {
    // Establish this source identity before the SDK child is created. Later
    // native-folder admission extends this held root rather than rebinding it.
    let root_units: Vec<_> = root.as_os_str().encode_wide().collect();
    let root_units = root_units
        .strip_prefix(&[92, 92, 63, 92])
        .unwrap_or(&root_units);
    ensure!(
        root_units.len() > 3 && root_units[1..3] == [58, 92],
        "fixed root drive shape differs"
    );
    let mut volume = effective_fixed_volume(root_units[0])?;
    let mut handles = vec![open_directory(HANDLE::default(), &mut volume)?];
    let mut filesystem = [0u16; 32];
    unsafe {
        GetVolumeInformationByHandleW(
            handle(&handles[0]),
            None,
            None,
            None,
            None,
            Some(&mut filesystem),
        )
    }
    .map_err(|_| anyhow::anyhow!("fixed volume filesystem query refused"))?;
    ensure!(
        filesystem.split(|u| *u == 0).next() == Some(&[78, 84, 70, 83][..]),
        "private environment requires fixed NTFS volume"
    );
    for part in root_units[3..].split(|unit| *unit == 92) {
        let mut part = part.to_vec();
        handles.push(open_directory(handle(handles.last().unwrap()), &mut part)?);
    }
    Ok(FixtureCustody {
        directories: handles,
        drive: root_units[0],
        volume,
        root_units: root_units.to_vec(),
    })
}

fn pin_private_directories(
    fixture: &FixtureCustody,
    expected: &ExpectedEnvironment,
) -> Result<Vec<OwnedHandle>> {
    ensure!(
        effective_fixed_volume(fixture.drive)? == fixture.volume,
        "fixed drive mapping changed before native folder query"
    );
    let native: Vec<_> = expected.local_app_data.as_os_str().encode_wide().collect();
    let native = native.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&native);
    let mut handles = Vec::new();
    for part in native[fixture.root_units.len() + 1..]
        .split(|unit| *unit == 92)
        .chain(std::iter::once(&[84, 101, 109, 112][..]))
    {
        let mut part = part.to_vec();
        let parent = handles
            .last()
            .unwrap_or_else(|| fixture.directories.last().unwrap());
        handles.push(open_directory(handle(parent), &mut part)?);
    }
    // Sample the effective/global mount again; no alias changes are performed.
    ensure!(
        effective_fixed_volume(fixture.drive)? == fixture.volume,
        "fixed drive mapping changed during query"
    );
    Ok(handles)
}

pub(super) fn expected_from_child(
    process: &OwnedHandle,
    fixture: &FixtureCustody,
    root: &Path,
    caller: &CallerEnvironment,
) -> Result<NativeEnvironmentCustody> {
    caller.require_unchanged()?;
    let folder = native_folder(process)?;
    caller.require_unchanged()?;
    let expected =
        match ExpectedEnvironment::from_caller_profile(root, &caller.local_app_data, &folder) {
            Ok(expected) => expected,
            Err(error) => {
                eprintln!(
                    "{}",
                    classify_profile_refusal(
                        &caller.local_app_data,
                        &folder,
                        caller.startup.local_app_data(),
                        ordinal_equal,
                    )
                );
                return Err(error.into());
            }
        };
    let directories = pin_private_directories(fixture, &expected)?;
    caller.require_unchanged()?;
    Ok(NativeEnvironmentCustody {
        expected,
        _directories: directories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Native filesystem-only regression, deliberately separate from the six
    // pure parser tests. No child/token/profile/PSEC operation or ACL mutation.
    #[test]
    fn directory_custody_blocks_rename_until_handles_close_without_spawning() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("fixed-owned-directory");
        let moved = directory.path().join("fixed-renamed-directory");
        std::fs::create_dir(&root).unwrap();
        let units: Vec<u16> = root.as_os_str().encode_wide().collect();
        let units = units.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&units);
        assert!(units.len() > 3 && units[1..3] == [58, 92]);
        let mut native = effective_fixed_volume(units[0]).unwrap();
        native.extend_from_slice(&units[3..]);
        let name = unicode(&mut native).unwrap();
        let attrs = attributes(HANDLE::default(), &name, 0x40 | 0x1000);
        let mut raw = HANDLE::default();
        let mut status = IO_STATUS_BLOCK::default();
        // Positive control for the exact former attribute-only open. Its
        // missing delete share does not itself pin this fresh directory name.
        assert!(
            unsafe { NtOpenFile(&mut raw, 0x0010_0080, &attrs, &mut status, 1, 0x0020_0021) }.0
                >= 0
        );
        let attributes_only = owned(raw).unwrap();
        std::fs::rename(&root, &moved).unwrap();
        std::fs::rename(&moved, &root).unwrap();
        drop(attributes_only);

        // Exercise the actual held-volume/ancestor production helper, without
        // looking up any process token or native profile.
        let custody = pin_fixture_root(&root).unwrap();
        let error = std::fs::rename(&root, &moved).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32)); // ERROR_SHARING_VIOLATION
        let sibling = root.join("fixed-public-sibling.txt");
        std::fs::write(&sibling, b"fixed public data").unwrap();
        std::fs::remove_file(sibling).unwrap();
        drop(custody);
        std::fs::rename(&root, &moved).unwrap();
        std::fs::rename(&moved, &root).unwrap();
    }

    #[test]
    fn returned_sid_pointer_and_body_must_fit_the_fixed_native_result() {
        let mut bytes = [0u8; 96];
        bytes[16] = 1;
        bytes[17] = 2;
        let base = bytes.as_ptr() as usize;
        assert_eq!(sid_range(&bytes, base + 16).unwrap(), 16..32);
        for pointer in [0, base, base + 95, base + bytes.len(), usize::MAX] {
            assert!(sid_range(&bytes, pointer).is_err());
        }
        bytes[17] = 16;
        assert!(sid_range(&bytes, base + 16).is_err());
        bytes[17] = 15;
        assert!(sid_range(&bytes[..32], base + 16).is_err());
    }
}
