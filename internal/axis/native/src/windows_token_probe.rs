// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Unwired diagnostic: call only inside the SDK's same-child pre-Resume admit
//! callback. No process creation, PID lookup, token setter or hook admission.
pub(crate) use crate::wire::NativeTokenObservation as TokenObservation;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::ptr;

const TOKEN_QUERY: u32 = 8;
const TOKEN_USER: u32 = 1;
const TOKEN_TYPE: u32 = 8;
const TOKEN_SESSION_ID: u32 = 12;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;
const TOKEN_IS_APP_CONTAINER: u32 = 29;
const TOKEN_APP_CONTAINER_SID: u32 = 31;
const CAPACITY: usize = 1024;
const _: () = assert!(std::mem::size_of::<usize>() == 8);
type Handle = *mut c_void;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refused;
type Result<T> = std::result::Result<T, Refused>;

// No Debug/Display/Serialize/Clone: binary identity never leaves this module.
struct Sid {
    bytes: [u8; 68],
    used: usize,
}
impl Sid {
    fn value(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
impl Drop for Sid {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        self.used = 0;
    }
}
struct Buffer([usize; CAPACITY / std::mem::size_of::<usize>()]);
impl Drop for Buffer {
    fn drop(&mut self) {
        for word in &mut self.0 {
            unsafe { ptr::write_volatile(word, 0) };
        }
    }
}

fn pointed_sid(bytes: &[u8], header: usize, nullable: bool) -> Result<Option<Sid>> {
    if header < 8 || bytes.len() < header || bytes.len() > CAPACITY {
        return Err(Refused);
    }
    let address = usize::from_ne_bytes(bytes[..8].try_into().map_err(|_| Refused)?);
    if address == 0 && nullable {
        return Ok(None);
    }
    let offset = address
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or(Refused)?;
    if address % 4 != 0
        || offset < header
        || offset.checked_add(8).is_none_or(|end| end > bytes.len())
    {
        return Err(Refused);
    }
    let count = bytes[offset + 1] as usize;
    if bytes[offset] != 1 || !(1..=15).contains(&count) {
        return Err(Refused);
    }
    let length = 8 + 4 * count;
    let end = offset.checked_add(length).ok_or(Refused)?;
    if end > bytes.len() {
        return Err(Refused);
    }
    let mut sid = Sid {
        bytes: [0; 68],
        used: length,
    };
    sid.bytes[..length].copy_from_slice(&bytes[offset..end]);
    Ok(Some(sid))
}
fn scalar(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_ne_bytes(bytes.try_into().map_err(|_| Refused)?))
}
fn integrity(bytes: &[u8]) -> Result<u32> {
    let sid = pointed_sid(bytes, 16, false)?.ok_or(Refused)?;
    let raw = sid.value();
    // SECURITY_MANDATORY_LABEL_AUTHORITY, exactly one integrity RID.
    if raw.len() != 12 || raw[1] != 1 || raw[2..8] != [0, 0, 0, 0, 0, 16] {
        return Err(Refused);
    }
    Ok(u32::from_ne_bytes(
        raw[8..12].try_into().map_err(|_| Refused)?,
    ))
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThread() -> Handle;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn ExitProcess(code: u32) -> !;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn OpenThreadToken(thread: Handle, access: u32, as_self: i32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        bytes: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}
struct Token(Handle);
impl Token {
    fn valid(&self) -> bool {
        !self.0.is_null() && self.0 as isize != -1
    }
    fn open(process: Handle) -> Result<Self> {
        let mut raw = ptr::null_mut();
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) };
        let token = Self(raw); // own any allocated nonnull handle BEFORE refusal
        if ok == 0 || !token.valid() {
            return Err(Refused); // checked Drop also handles allocated refusal
        }
        Ok(token)
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        let raw = std::mem::replace(&mut self.0, ptr::null_mut());
        if !raw.is_null() && raw as isize != -1 && unsafe { CloseHandle(raw) } == 0 {
            // No retry of an uncertain handle and no success record. The same
            // trusted peer's independent Go Job remains final cleanup owner.
            unsafe { ExitProcess(70) }
        }
    }
}
fn no_thread_impersonation() -> Result<()> {
    let mut raw = ptr::null_mut();
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    let status = unsafe { GetLastError() }; // immediate; never formatted/output
    let token = Token(raw);
    if ok != 0 || !raw.is_null() || status != 1008 {
        return Err(Refused);
    }
    drop(token);
    Ok(())
}
fn information<T>(token: &Token, class: u32, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
    let mut buffer = Buffer([0; CAPACITY / std::mem::size_of::<usize>()]);
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.0.as_mut_ptr().cast(),
            CAPACITY as u32,
            &mut returned,
        )
    } == 0
        || returned == 0
        || returned as usize > CAPACITY
    {
        return Err(Refused);
    }
    // Parse before moving/dropping the stack buffer: native pointers remain
    // anchored to this exact allocation. No allocation uses an OS length.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.0.as_ptr().cast::<u8>(), returned as usize) };
    read(bytes)
}
fn summarize(
    user: &Sid,
    peer_user: &Sid,
    container: Option<&Sid>,
    is_container: u32,
    rid: u32,
    session: u32,
    peer_session: u32,
) -> TokenObservation {
    TokenObservation {
        diagnostic_only: true,
        authorization_granted: false,
        query_complete: true,
        primary_token: true,
        user_sid_valid: true,
        user_matches_peer: user.value() == peer_user.value(),
        app_container_sid_present: container.is_some(),
        app_container_sid_valid: container.is_some(),
        // Microsoft defines this DWORD as nonzero, not exclusively1.
        token_is_app_container: is_container != 0,
        integrity_rid: rid,
        token_session_id: session,
        session_matches_peer: session == peer_session,
        token_handles_closed: true, // checked token Drops complete before return
    }
}

// The argument is borrowed from SDK admit_and_resume, not a reopened PID or
// guest-selected handle. This helper alone does NOT establish suspendedness:
// the SDK's pre/post callback Job/class44/live guards supply that seam.
// False measured facts grant no authority and are not silently rewritten.
pub(crate) fn query_pre_resume(child: &OwnedHandle) -> Result<TokenObservation> {
    no_thread_impersonation()?;
    let facts = {
        let peer = Token::open(unsafe { GetCurrentProcess() })?;
        let child = Token::open(child.as_raw_handle())?;
        if information(&peer, TOKEN_TYPE, scalar)? != 1
            || information(&child, TOKEN_TYPE, scalar)? != 1
        {
            return Err(Refused);
        }
        let peer_user =
            information(&peer, TOKEN_USER, |b| pointed_sid(b, 16, false))?.ok_or(Refused)?;
        let user =
            information(&child, TOKEN_USER, |b| pointed_sid(b, 16, false))?.ok_or(Refused)?;
        let container = information(&child, TOKEN_APP_CONTAINER_SID, |b| pointed_sid(b, 8, true))?;
        let is_container = information(&child, TOKEN_IS_APP_CONTAINER, scalar)?;
        let rid = information(&child, TOKEN_INTEGRITY_LEVEL, integrity)?;
        let session = information(&child, TOKEN_SESSION_ID, scalar)?;
        let peer_session = information(&peer, TOKEN_SESSION_ID, scalar)?;
        summarize(
            &user,
            &peer_user,
            container.as_ref(),
            is_container,
            rid,
            session,
            peer_session,
        )
    }; // both token handles close exactly once, checked, before success escapes
    no_thread_impersonation()?;
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(header: usize, authority: u8, rid: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; header + 12];
        let address = bytes.as_ptr() as usize + header;
        bytes[..8].copy_from_slice(&address.to_ne_bytes());
        bytes[header] = 1;
        bytes[header + 1] = 1;
        bytes[header + 7] = authority;
        bytes[header + 8..header + 12].copy_from_slice(&rid.to_ne_bytes());
        bytes
    }
    #[test]
    fn sid_pointer_requires_complete_canonical_sid_after_correct_header() {
        for header in [8, 16] {
            let mut bytes = fixture(header, 5, 21);
            assert_eq!(
                pointed_sid(&bytes, header, false)
                    .unwrap()
                    .unwrap()
                    .value()
                    .len(),
                12
            );
            for address in [
                0,
                bytes.as_ptr() as usize,
                bytes.as_ptr() as usize + header - 4,
                bytes.as_ptr() as usize + header + 1,
                usize::MAX,
            ] {
                bytes[..8].copy_from_slice(&address.to_ne_bytes());
                assert!(pointed_sid(&bytes, header, false).is_err());
            }
        }
        for (revision, count) in [(0, 1), (2, 1), (1, 0), (1, 16), (1, 2)] {
            let mut bytes = fixture(16, 5, 21);
            bytes[16] = revision;
            bytes[17] = count;
            assert!(pointed_sid(&bytes, 16, false).is_err());
        }
        let mut maximum = vec![0u8; 16 + 68];
        let address = maximum.as_ptr() as usize + 16;
        maximum[..8].copy_from_slice(&address.to_ne_bytes());
        maximum[16] = 1;
        maximum[17] = 15;
        assert_eq!(
            pointed_sid(&maximum, 16, false)
                .unwrap()
                .unwrap()
                .value()
                .len(),
            68
        );
        maximum.pop();
        assert!(pointed_sid(&maximum, 16, false).is_err());
        assert!(pointed_sid(&[0u8; CAPACITY + 1], 16, false).is_err());
    }
    #[test]
    fn null_container_and_nonzero_flag_remain_independent_observations() {
        assert!(pointed_sid(&[0u8; 8], 8, true).unwrap().is_none());
        assert!(pointed_sid(&[0u8; 8], 8, false).is_err());
        let bytes = fixture(16, 5, 21);
        let user = pointed_sid(&bytes, 16, false).unwrap().unwrap();
        for raw in [0, 1, 2, u32::MAX] {
            let facts = summarize(&user, &user, None, raw, 4096, 0, 0);
            assert_eq!(facts.token_is_app_container, raw != 0);
            assert!(!facts.app_container_sid_present && !facts.app_container_sid_valid);
        }
        let other_bytes = fixture(16, 5, 22);
        let other = pointed_sid(&other_bytes, 16, false).unwrap().unwrap();
        let facts = summarize(&user, &other, Some(&user), 0, 8192, 2, 1);
        assert!(!facts.user_matches_peer && !facts.session_matches_peer);
        assert!(
            facts.app_container_sid_present
                && facts.app_container_sid_valid
                && !facts.token_is_app_container
        );
    }
    #[test]
    fn scalar_and_integrity_results_have_exact_bounded_shapes() {
        for bytes in [&[][..], &[0u8; 3][..], &[0u8; 5][..]] {
            assert!(scalar(bytes).is_err());
        }
        assert_eq!(scalar(&u32::MAX.to_ne_bytes()).unwrap(), u32::MAX);
        for rid in [0, 4096, 8192, u32::MAX] {
            let bytes = fixture(16, 16, rid);
            assert_eq!(integrity(&bytes).unwrap(), rid);
        }
        assert!(integrity(&fixture(16, 5, 8192)).is_err());
        assert!(integrity(&[0u8; 16]).is_err());
    }
    #[test]
    fn closed_observation_contains_only_booleans_and_numbers() {
        let bytes = fixture(16, 5, 21);
        let user = pointed_sid(&bytes, 16, false).unwrap().unwrap();
        let record = summarize(&user, &user, None, 0, 4096, 1, 1);
        let json = serde_json::to_value(record).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 13);
        assert_eq!(
            object.get("diagnostic_only"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            object.get("authorization_granted"),
            Some(&serde_json::json!(false))
        );
        assert!(object.values().all(|v| v.is_boolean() || v.is_u64()));
        assert!(
            object.get("error").is_none()
                && object.get("sid").is_none()
                && object.get("pid").is_none()
        );
    }
}

#[cfg(feature = "windows-conpty-diagnostic")]
pub(crate) fn diagnostic_non_elevated() -> Result<()> {
    no_thread_impersonation()?;
    let token = Token::open(unsafe { GetCurrentProcess() })?;
    if information(&token, 20, scalar)? != 0 {
        return Err(Refused);
    }
    drop(token);
    no_thread_impersonation()
}
