// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("the fixed ConPTY diagnostic requires native Windows x86_64");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() {
    defenseclaw_axis_native::windows_conpty_diagnostic::entry()
}
