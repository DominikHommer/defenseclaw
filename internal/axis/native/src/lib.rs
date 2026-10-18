// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the initial private AXIS peer supports only native Linux x86_64");

pub mod conversation;
pub mod custody;
pub mod linux;
pub mod owner;
pub mod transport;
pub mod wire;
