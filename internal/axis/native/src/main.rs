// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Private stdio entry point. No command/path/env option or customer activation.

use defenseclaw_axis_native::linux::LinuxEngine;
use defenseclaw_axis_native::owner::Owner;
use defenseclaw_axis_native::transport::Transport;
use std::fs::File;
use std::os::fd::FromRawFd;

fn run() -> Result<(), ()> {
    // The host creates this peer as init of a fresh outer PID namespace. Its
    // parent is outside that namespace and is therefore reported as PID zero.
    // Install parent-death handling here, rather than comparing a host PID in
    // Go's post-clone hook. Protocol EOF still refuses the earlier host-death
    // race; a creating-thread death may kill this peer early (availability).
    // SAFETY: these queries and prctl affect only this single-threaded peer.
    if unsafe { libc::getpid() != 1 || libc::getppid() != 0 }
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
    {
        return Err(());
    }
    defenseclaw_axis_native::namespace::setup()?;
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    // No threads/library backend have started. The trusted factory supplies a
    // credential-free environment; remove any accidental inherited override
    // before native preparation. No value is logged or retained in a plan.
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    for name in names {
        // SAFETY: the peer is single threaded throughout its lifetime.
        unsafe { std::env::remove_var(name) };
    }
    // Mark every inherited nonstdio descriptor close-on-exec before any library
    // can open another. Preparation consumes only its exact fixed capability
    // table; the SDK selectively duplicates/passes owned mount/filter inputs.
    // SAFETY: close_range CLOEXEC only changes this child's descriptor flags.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } < 0
    {
        return Err(());
    }
    // SAFETY: the private factory transfers ownership of stdin/stdout to this
    // entry point once. No Rust stdio wrapper is constructed for either one.
    let input = unsafe { File::from_raw_fd(0) };
    let output = unsafe { File::from_raw_fd(1) };
    let transport = Transport::new(input, output).map_err(|_| ())?;
    Owner::new(LinuxEngine, transport).run().map_err(|_| ())
}

fn main() {
    // Diagnostics cannot hold process exit behind a blocked host stderr pipe.
    // SAFETY: only this peer's stderr status flags are changed.
    unsafe {
        let flags = libc::fcntl(2, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(2, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    if run().is_err() {
        // A fixed diagnostic cannot disclose arguments, environment, policy or
        // host paths. The Go owner treats EOF/failure as containment required.
        const DIAGNOSTIC: &[u8] = b"axis_private_peer_failed\n";
        // SAFETY: fixed initialized bytes; one nonblocking best-effort write.
        unsafe { libc::write(2, DIAGNOSTIC.as_ptr().cast(), DIAGNOSTIC.len()) };
        std::process::exit(1);
    }
}
