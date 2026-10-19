// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Diagnostic-only use of the existing SDK retained-child launch seam.
//! This never consumes the process owner or binds a hook endpoint.
use crate::windows_token_probe::{TokenObservation, query_pre_resume};
use mxc_sdk::v1::OwnedPsecProcess;
use std::io;

/// The caller retains `process` on BOTH Ok and Err and must drive the existing
/// Owner's Stop/try_wait cleanup before dependent capabilities are released.
/// `live` comes from that same owner lifetime, never an always-success callback.
/// This probe has no bound endpoint: the seal is deliberately an empty action.
/// This function must not be reused for hook admission with a no-op seal.
pub(crate) fn observe_and_resume(
    process: &mut OwnedPsecProcess,
    live: impl FnMut() -> io::Result<()>,
) -> io::Result<TokenObservation> {
    let mut observation = None;
    process.admit_and_resume(
        live,
        |child| {
            observation = Some(
                query_pre_resume(child)
                    .map_err(|_| io::Error::other("native token observation refused"))?,
            );
            Ok(())
        },
        || {},
    )?;
    // No observation can escape on query, custody, cancellation or Resume
    // refusal. The SDK has completed Resume before this successful return.
    observation.ok_or_else(|| io::Error::other("native token observation absent"))
}
