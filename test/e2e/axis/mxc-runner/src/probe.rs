// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail, ensure};
use axis_core::policy::Policy;
use axis_sandbox::linux::{landlock, seccomp};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, MxcProcess, MxcPtyProcess, MxcPtySize,
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, SpawnOptions,
    SpawnWithPtyOptions, StreamCloser, TelemetryConfig, WaitResult,
};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const AXIS_COMMIT: &str = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c";
const MXC_COMMIT: &str = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
const PREFIX: &str = "dc-axis-mxc-";
const SEAL: &[u8] = b"defenseclaw-fixed-mxc-contributor-fixture-v1\n";
const READONLY: &[u8] = b"synthetic-readonly-canary\n";
const UNGRANTED: &[u8] = b"synthetic-ungranted-canary\n";
const OUTPUT_LIMIT: usize = 64 * 1024;
const DIAGNOSTIC_LIMIT: usize = 8 * 1024;
const SUPERVISOR_LIMIT: Duration = Duration::from_secs(15);

pub fn run() -> Result<i32> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "--fixed-child" {
        return match args[1].to_str() {
            Some("boundaries") => fixed_child(Case::Boundaries),
            Some("pty") => fixed_child(Case::Pty),
            Some("timeout") => fixed_child(Case::Timeout),
            _ => bail!("unknown fixed child case"),
        };
    }
    ensure!(
        args.is_empty(),
        "the probe accepts no command, path or policy arguments"
    );
    // This experiment is for rootless operation, without host setup mutations.
    // SAFETY: geteuid has no pointer arguments and does not mutate process state.
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as an unprivileged user"
    );
    let abi = landlock_abi()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let owned = tempfile::Builder::new().prefix(PREFIX).tempdir_in("/tmp")?;
    let paths = Paths::create(&owned.path().canonicalize()?)?;

    // Before invoking any SDK code or creating threads, remove credentials,
    // proxy overrides, dynamic-loader overrides and caller-selected tool paths
    // from the supervisor too. No inherited environment is logged or retained.
    private_supervisor_environment(&paths)?;
    run_piped(&paths, &executable, Case::Boundaries)?;
    run_pty(&paths, &executable)?;
    run_piped(&paths, &executable, Case::Timeout)?;
    ensure!(
        fs::read(&paths.readonly)? == READONLY,
        "readonly canary changed"
    );
    ensure!(
        fs::read(paths.ungranted.join("canary"))? == UNGRANTED,
        "ungranted canary changed"
    );
    ensure!(
        !paths.ungranted.join("write-attempt").exists(),
        "ungranted write survived"
    );
    for directory in [&paths.workspace, &paths.home, &paths.temporary] {
        ensure!(
            fs::read(directory.join("allowed-write"))? == b"fixed-benign-write\n",
            "allowed write missing"
        );
    }
    let root = owned.path().to_owned();
    owned
        .close()
        .context("remove owned fixture after all SDK handles returned")?;
    ensure!(!root.exists(), "owned fixture cleanup was incomplete");
    println!(
        "{}",
        serde_json::json!({
            "axis_commit": AXIS_COMMIT, "mxc_commit": MXC_COMMIT,
            "containment": "mxc_sdk_v1_bubblewrap", "axis_child_guards": "landlock_and_offline_seccomp",
            "landlock_abi": abi, "filesystem": "hard_requirement", "network": "block",
            "checks": ["private_home_and_environment", "allowed_writes", "ungranted_read_and_write_eacces",
                "readonly_write_denied", "ipv4_ipv6_tcp_udp_socket_eperm", "exit_23", "pty_isatty_and_foreground",
                "pty_input_ack_and_resize", "typed_timeout", "direct_child_pidfd_exited",
                "handle_kill_after_wait_idempotent", "owned_fixture_removed"],
            "scope": "fixed_benign_contributor_experiment", "production_or_claude_qualification": false,
            "proxy_or_descendant_cleanup_qualification": false
        })
    );
    Ok(0)
}

#[derive(Clone, Copy)]
enum Case {
    Boundaries,
    Pty,
    Timeout,
}

impl Case {
    fn argument(self) -> &'static str {
        match self {
            Self::Boundaries => "boundaries",
            Self::Pty => "pty",
            Self::Timeout => "timeout",
        }
    }
}

struct Paths {
    root: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    readonly: PathBuf,
    ungranted: PathBuf,
}

impl Paths {
    fn at(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            workspace: root.join("workspace"),
            home: root.join("home"),
            temporary: root.join("tmp"),
            readonly: root.join("readonly"),
            ungranted: root.join("ungranted"),
        }
    }

    fn create(root: &Path) -> Result<Self> {
        let paths = Self::at(root);
        for directory in [
            &paths.workspace,
            &paths.home,
            &paths.temporary,
            &paths.ungranted,
        ] {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        for directory in [
            paths.home.join(".config"),
            paths.home.join(".cache"),
            paths.home.join(".local/share"),
        ] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        write_new(&root.join("fixture-seal"), SEAL)?;
        write_new(&paths.readonly, READONLY)?;
        write_new(&paths.ungranted.join("canary"), UNGRANTED)?;
        Ok(paths)
    }

    fn from_child() -> Result<Self> {
        let workspace = std::env::current_dir()?.canonicalize()?;
        ensure!(
            workspace
                .file_name()
                .is_some_and(|name| name == "workspace"),
            "unexpected child cwd"
        );
        let root = workspace.parent().context("missing fixture parent")?;
        ensure!(
            root.parent() == Some(fs::canonicalize("/tmp")?.as_path()),
            "fixture is outside private temp parent"
        );
        ensure!(
            root.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(PREFIX)),
            "unexpected fixture name"
        );
        let metadata = fs::symlink_metadata(root)?;
        // SAFETY: geteuid is a read-only identity query.
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o700,
            "fixture ownership or mode differs"
        );
        ensure!(
            fs::read(root.join("fixture-seal"))? == SEAL,
            "fixture seal differs"
        );
        let paths = Self::at(root);
        for directory in [
            &paths.workspace,
            &paths.home,
            &paths.temporary,
            &paths.ungranted,
        ] {
            ensure!(
                fs::symlink_metadata(directory)?.is_dir()
                    && directory.canonicalize()? == *directory,
                "fixture directory is not canonical"
            );
        }
        verify_environment(&paths)?;
        Ok(paths)
    }

    fn environment(&self) -> Result<Vec<(String, String)>> {
        Ok(vec![
            ("HOME".into(), text(&self.home)?.into()),
            ("TMPDIR".into(), text(&self.temporary)?.into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
            ("TERM".into(), "xterm".into()),
            (
                "XDG_CONFIG_HOME".into(),
                text(&self.home.join(".config"))?.into(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                text(&self.home.join(".cache"))?.into(),
            ),
            (
                "XDG_DATA_HOME".into(),
                text(&self.home.join(".local/share"))?.into(),
            ),
        ])
    }

    fn request(&self, executable: &Path, case: Case) -> Result<ContainerRequest> {
        // The only shell operation is exec of this exact binary and a fixed case.
        // MXC's public SDK currently accepts a shell command string rather than argv.
        let command = format!(
            "exec {} --fixed-child {}",
            shell_quote(text(executable)?),
            case.argument()
        );
        Ok(ContainerRequest {
            containment: Containment::Bubblewrap,
            filesystem: Some(FilesystemPolicy {
                // The entire synthetic fixture is visible read-only to MXC;
                // its explicit writable subdirectories override that mount.
                // The ungranted synthetic canary is deliberately writable at
                // the MXC layer so EACCES proves the inner AXIS restriction.
                readonly_paths: vec![text(&self.root)?.into(), text(executable)?.into()],
                readwrite_paths: [
                    &self.workspace,
                    &self.home,
                    &self.temporary,
                    &self.ungranted,
                ]
                .iter()
                .map(|path| text(path).map(str::to_owned))
                .collect::<Result<_>>()?,
                denied_paths: Vec::new(),
                clear_policy_on_exit: Some(true),
            }),
            network: Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    default: Some(NetworkAction::Deny),
                    ..Default::default()
                }),
                ingress: Some(NetworkIngressPolicy {
                    default: Some(NetworkAction::Deny),
                    host_loopback: Some(NetworkAction::Deny),
                }),
                runtime_config: None,
            }),
            timeout_ms: Some(if matches!(case, Case::Timeout) {
                1_000
            } else {
                10_000
            }),
            working_directory: Some(text(&self.workspace)?.into()),
            environment: Some(self.environment()?),
            inherit_default_environment: Some(false),
            ..ContainerRequest::new(command)
        })
    }

    fn axis_policy(&self, executable: &Path) -> Result<Policy> {
        let mut readonly = vec![executable.to_owned(), self.readonly.clone()];
        // Grant only runtime installation paths. MXC's broader baseline /etc
        // mount is not granted by the AXIS child policy.
        for path in [
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/etc/ld.so.cache",
            "/dev/null",
        ] {
            if Path::new(path).exists() {
                readonly.push(PathBuf::from(path));
            }
        }
        let value = serde_json::json!({
            "version": 1, "name": "dc-mxc-offline-child",
            "runtime": {"containment": "process", "provider": "mxc"},
            "filesystem": {"compatibility": "hard_requirement", "read_only": readonly,
                "read_write": [&self.workspace, &self.home, &self.temporary]},
            // Resource limits are deliberately outside this experiment. MXC
            // owns the real configured wall-clock timeout.
            "process": {"max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0},
            "network": {"mode": "block"}
        });
        Policy::from_yaml(&serde_json::to_string(&value)?)
            .context("validate fixed AXIS child policy")
    }
}

fn private_supervisor_environment(paths: &Paths) -> Result<()> {
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    // SAFETY: this is called once, before any SDK API or thread is started.
    unsafe {
        for name in names {
            std::env::remove_var(name);
        }
        for (name, value) in paths.environment()? {
            std::env::set_var(name, value);
        }
    }
    Ok(())
}

fn verify_environment(paths: &Paths) -> Result<()> {
    let expected = paths.environment()?;
    for (name, value) in &expected {
        ensure!(
            std::env::var(name).ok().as_ref() == Some(value),
            "private environment value differs for {name}"
        );
    }
    for (name, value) in std::env::vars_os() {
        let key = name.to_str().context("non-UTF8 environment key")?;
        if expected.iter().any(|(allowed, _)| key == allowed) {
            continue;
        }
        // /bin/sh may synthesize these after MXC --clearenv. None contains
        // caller state: the supervisor's original environment was erased.
        match key {
            "PWD" => ensure!(value == paths.workspace.as_os_str(), "shell cwd differs"),
            "SHLVL" => ensure!(
                value
                    .to_str()
                    .is_some_and(|level| matches!(level, "0" | "1" | "2")),
                "shell nesting differs"
            ),
            "_" => {}
            _ => bail!("unexpected environment key"),
        }
    }
    Ok(())
}

fn fixed_child(case: Case) -> Result<i32> {
    let paths = Paths::from_child()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let policy = paths.axis_policy(&executable)?;
    landlock_abi()?;
    // SAFETY: PR_SET_NO_NEW_PRIVS has an integer value and unused zero args.
    // It affects only this already-contained fixed child and is irreversible.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "setting no_new_privs failed: {}",
        io::Error::last_os_error()
    );
    landlock::apply_landlock(&policy.filesystem, &paths.workspace)
        .map_err(|error| anyhow!(error))?;
    seccomp::apply_offline_mxc_child_seccomp(&policy.process, matches!(case, Case::Pty))
        .map_err(|error| anyhow!(error))?;
    match case {
        Case::Boundaries => {
            ensure!(
                fs::read(&paths.readonly)? == READONLY,
                "granted read differs"
            );
            for directory in [&paths.workspace, &paths.home, &paths.temporary] {
                write_new(&directory.join("allowed-write"), b"fixed-benign-write\n")?;
            }
            denied_errno(
                fs::read(paths.ungranted.join("canary")),
                &[libc::EACCES],
                "ungranted read",
            )?;
            denied_errno(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(paths.ungranted.join("write-attempt")),
                &[libc::EACCES],
                "ungranted write",
            )?;
            denied_errno(
                OpenOptions::new().write(true).open(&paths.readonly),
                &[libc::EACCES, libc::EROFS],
                "readonly write",
            )?;
            for family in [libc::AF_INET, libc::AF_INET6] {
                for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
                    // SAFETY: socket receives constant family/type/protocol.
                    let descriptor = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
                    if descriptor >= 0 {
                        // SAFETY: a successful socket call returns a new fd.
                        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
                        bail!("IP socket creation was permitted");
                    }
                    ensure!(
                        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
                        "IP socket denial was not EPERM"
                    );
                }
            }
            println!("BOUNDARIES_OK");
            Ok(23)
        }
        Case::Pty => {
            terminal_state(30, 100)?;
            println!("PTY_READY isatty=true foreground=true rows=30 cols=100");
            io::stdout().flush()?;
            let mut line = String::new();
            // Input is bounded even if the fixed supervisor is changed later.
            io::stdin().lock().take(128).read_line(&mut line)?;
            ensure!(
                line == "fixed-benign-input\n",
                "PTY input acknowledgement differs"
            );
            terminal_state(40, 120)?;
            println!("PTY_ACK input=true rows=40 cols=120 foreground=true");
            Ok(23)
        }
        Case::Timeout => {
            println!("TIMEOUT_READY");
            io::stdout().flush()?;
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn terminal_state(rows: u16, cols: u16) -> Result<()> {
    // SAFETY: all queries use the owned stdin fd and valid stack output memory.
    let (tty, foreground, group) =
        unsafe { (libc::isatty(0), libc::tcgetpgrp(0), libc::getpgrp()) };
    ensure!(
        tty == 1 && foreground >= 0 && foreground == group,
        "PTY is not the foreground terminal"
    );
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes a winsize to the supplied stack pointer.
    ensure!(
        unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) } == 0,
        "PTY size query failed"
    );
    ensure!(
        size.ws_row == rows && size.ws_col == cols,
        "child PTY dimensions differ"
    );
    Ok(())
}

fn run_piped(paths: &Paths, executable: &Path, case: Case) -> Result<()> {
    let mut process = v1::spawn(
        paths.request(executable, case)?,
        SpawnOptions {
            telemetry: disabled_telemetry(),
        },
    )
    .context("explicit MXC Bubblewrap spawn refused")?;
    let result = (|| {
        let tracked = TrackedChild::new(process.id())?;
        ensure!(
            process.warnings().is_empty(),
            "MXC returned policy or execution warnings"
        );
        let stdout = Capture::start(
            process.take_stdout().context("missing SDK stdout pipe")?,
            process.stdout_closer(),
        );
        let stderr = Capture::start(
            process.take_stderr().context("missing SDK stderr pipe")?,
            process.stderr_closer(),
        );
        drop(process.take_stdin());
        let outcome = wait_process(&mut process)?;
        ensure!(
            process.warnings().is_empty(),
            "MXC returned teardown warnings"
        );
        let output = stdout.finish()?;
        let errors = stderr.finish()?;
        if !errors.is_empty() {
            // This child receives only our synthetic fixture and private
            // environment. Preserve its actual refusal without dumping host
            // environment, unbounded output or terminal control characters.
            eprintln!(
                "AXIS_MXC_FIXED_CHILD_DIAGNOSTIC={}",
                fixed_child_diagnostic(case, &outcome, &errors)
            );
        }
        ensure!(errors.is_empty(), "fixed child wrote stderr");
        match case {
            Case::Boundaries => {
                ensure!(
                    matches!(outcome, WaitResult::Exited(23)),
                    "boundary child exit was not 23"
                );
                ensure!(
                    contains(&output, b"BOUNDARIES_OK"),
                    "boundary acknowledgement missing"
                );
            }
            Case::Timeout => {
                ensure!(
                    matches!(outcome, WaitResult::TimedOut),
                    "MXC did not report its typed timeout"
                );
                ensure!(
                    contains(&output, b"TIMEOUT_READY"),
                    "timeout occurred before guarded payload readiness"
                );
            }
            Case::Pty => bail!("PTY case cannot use pipes"),
        }
        tracked.require_exited()?;
        // SDK-owned handle cleanup after wait must not signal a reused raw PID.
        process.kill()?;
        process.kill()?;
        Ok(())
    })();
    if result.is_err() {
        let killed = process.kill();
        let waited = process.wait();
        ensure!(
            killed.is_ok() && waited.is_ok(),
            "failed probe also failed tracked SDK cleanup"
        );
    }
    result.with_context(|| format!("fixed {} experiment", case.argument()))
}

fn run_pty(paths: &Paths, executable: &Path) -> Result<()> {
    let terminal = v1::spawn_with_pty(
        paths.request(executable, Case::Pty)?,
        SpawnWithPtyOptions {
            telemetry: disabled_telemetry(),
            size: terminal_size(30, 100),
        },
    )
    .context("explicit MXC Bubblewrap PTY spawn refused")?;
    let result = (|| {
        let tracked = TrackedChild::new(terminal.id())?;
        ensure!(
            terminal.warnings().is_empty(),
            "MXC returned PTY policy or execution warnings"
        );
        // Register the cloned reader before asking for its interrupt handle.
        let reader = terminal.try_clone_reader()?;
        let output = Capture::start(reader, terminal.stdout_closer());
        let mut input = terminal.take_writer()?;
        output.require_marker(
            b"PTY_READY isatty=true foreground=true rows=30 cols=100",
            Duration::from_secs(5),
        )?;
        terminal.resize(terminal_size(40, 120))?;
        let size = terminal.size()?;
        ensure!(
            size.rows == 40 && size.cols == 120,
            "SDK PTY resize readback differs"
        );
        input.write_all(b"fixed-benign-input\n")?;
        input.flush()?;
        ensure!(
            matches!(wait_terminal(&terminal)?, WaitResult::Exited(23)),
            "PTY child exit was not 23"
        );
        ensure!(
            terminal.warnings().is_empty(),
            "MXC returned PTY teardown warnings"
        );
        let bytes = output.finish()?;
        ensure!(
            contains(
                &bytes,
                b"PTY_ACK input=true rows=40 cols=120 foreground=true"
            ),
            "PTY input/resize acknowledgement missing"
        );
        tracked.require_exited()?;
        terminal.kill()?;
        terminal.kill()?;
        Ok(())
    })();
    if result.is_err() {
        let killed = terminal.kill();
        let waited = terminal.wait();
        ensure!(
            killed.is_ok() && waited.is_ok(),
            "failed PTY probe also failed tracked SDK cleanup"
        );
    }
    result.context("fixed MXC-owned PTY experiment")
}

fn wait_process(process: &mut MxcProcess) -> Result<WaitResult> {
    let start = Instant::now();
    loop {
        match process.try_wait() {
            Ok(Some(_)) => return Ok(process.wait()?),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(process.wait()?),
            Err(error) => return Err(error.into()),
            Ok(None) => {}
        }
        if start.elapsed() >= SUPERVISOR_LIMIT {
            process.kill_for_timeout()?;
            let _ = process.wait();
            bail!("supervisor deadline exceeded; backend timeout was not sufficient");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_terminal(terminal: &MxcPtyProcess) -> Result<WaitResult> {
    let start = Instant::now();
    loop {
        match terminal.try_wait() {
            Ok(Some(_)) => return Ok(terminal.wait()?),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(terminal.wait()?),
            Err(error) => return Err(error.into()),
            Ok(None) => {}
        }
        if start.elapsed() >= SUPERVISOR_LIMIT {
            terminal.kill_for_timeout()?;
            let _ = terminal.wait();
            bail!("supervisor PTY deadline exceeded");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    completed: mpsc::Receiver<Result<(), io::Error>>,
    reader: Option<JoinHandle<()>>,
    closer: Option<StreamCloser>,
}

impl Capture {
    fn start(mut stream: Box<dyn Read + Send>, closer: Option<StreamCloser>) -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&bytes);
        let (sender, completed) = mpsc::channel();
        let reader = thread::spawn(move || {
            let result = (|| {
                let mut buffer = [0u8; 4096];
                let mut overflow = false;
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            let mut output = captured
                                .lock()
                                .map_err(|_| io::Error::other("capture mutex poisoned"))?;
                            let remaining = OUTPUT_LIMIT.saturating_sub(output.len());
                            output.extend_from_slice(&buffer[..count.min(remaining)]);
                            overflow |= count > remaining;
                        }
                        // Linux PTY readers conventionally return EIO at EOF.
                        Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                if overflow {
                    return Err(io::Error::other("fixed child exceeded output limit"));
                }
                Ok(())
            })();
            let _ = sender.send(result);
        });
        Self {
            bytes,
            completed,
            reader: Some(reader),
            closer,
        }
    }

    fn require_marker(&self, marker: &[u8], limit: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if contains(
                &self
                    .bytes
                    .lock()
                    .map_err(|_| anyhow!("capture mutex poisoned"))?,
                marker,
            ) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        bail!("fixed child readiness acknowledgement missing");
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        // Prefer natural EOF so the final ACK is not truncated. After a process
        // exit, close the SDK stream if an inherited descriptor keeps it open.
        let result = match self.completed.recv_timeout(Duration::from_millis(500)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(closer) = &self.closer {
                    closer.close();
                }
                self.completed
                    .recv_timeout(Duration::from_secs(2))
                    .context("SDK stream close did not unblock capture")?
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| anyhow!("capture thread panicked"))?;
        }
        result.context("bounded fixed child capture")?;
        let output = self
            .bytes
            .lock()
            .map_err(|_| anyhow!("capture mutex poisoned"))?
            .clone();
        Ok(output)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(closer) = &self.closer {
            closer.close();
        }
        // An error path must not block forever joining a broken SDK reader.
        // The SDK process handle is killed and waited by its enclosing scope.
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }
}

struct TrackedChild(OwnedFd);

impl TrackedChild {
    fn new(id: u32) -> Result<Self> {
        ensure!(id > 0, "MXC did not expose its direct child identity");
        // SAFETY: pidfd_open binds an existing SDK-owned direct child, before
        // this caller performs any wait/reap. No numeric PID is ever signaled.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, id, 0) };
        ensure!(
            descriptor >= 0,
            "pidfd_open failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: a successful pidfd_open returned a new owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(descriptor as i32) }))
    }

    fn require_exited(&self) -> Result<()> {
        let mut pollfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized, valid stack pollfd.
        ensure!(
            unsafe { libc::poll(&mut pollfd, 1, 2_000) } == 1
                && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0,
            "tracked direct MXC child survived SDK wait"
        );
        Ok(())
    }
}

fn landlock_abi() -> Result<i64> {
    // SAFETY: VERSION with null attrs and zero size is a read-only ABI query.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    ensure!(
        abi >= 3,
        "Landlock ABI >= 3 is required; no guard downgrade is permitted"
    );
    Ok(abi as i64)
}

fn disabled_telemetry() -> Option<TelemetryConfig> {
    Some(TelemetryConfig {
        enabled: Some(false),
    })
}

fn terminal_size(rows: u16, cols: u16) -> MxcPtySize {
    MxcPtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn fixed_child_diagnostic(case: Case, outcome: &WaitResult, errors: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "scope": "fixed_synthetic_private_environment_contributor_child",
        "case": case.argument(),
        "outcome": format!("{outcome:?}"),
        "captured_stderr_bytes": errors.len(),
        "truncated": errors.len() > DIAGNOSTIC_LIMIT,
        "stderr": String::from_utf8_lossy(&errors[..errors.len().min(DIAGNOSTIC_LIMIT)])
    })
}

fn denied_errno<T>(result: io::Result<T>, allowed: &[i32], action: &str) -> Result<()> {
    match result {
        Err(error)
            if error
                .raw_os_error()
                .is_some_and(|code| allowed.contains(&code)) =>
        {
            Ok(())
        }
        _ => bail!("{action} did not return the required denial"),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("probe path is not UTF-8")
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_command_quotes_literal_shell_characters() {
        assert_eq!(shell_quote("/tmp/a'b $x`id`~"), "'/tmp/a'\\''b $x`id`~'");
    }

    #[test]
    fn unrelated_errno_is_not_a_denial_success() {
        assert!(
            denied_errno::<()>(
                Err(io::Error::from_raw_os_error(libc::ENOENT)),
                &[libc::EACCES],
                "read"
            )
            .is_err()
        );
        assert!(denied_errno::<()>(Ok(()), &[libc::EACCES], "read").is_err());
        assert!(
            denied_errno::<()>(
                Err(io::Error::from_raw_os_error(libc::EACCES)),
                &[libc::EACCES],
                "read"
            )
            .is_ok()
        );
    }

    #[test]
    fn fixed_child_diagnostics_are_bounded_and_json_escaped() {
        let mut errors = vec![0; DIAGNOSTIC_LIMIT];
        errors.extend_from_slice(b"not-in-diagnostic");
        let diagnostic = fixed_child_diagnostic(Case::Boundaries, &WaitResult::Exited(1), &errors);
        assert_eq!(diagnostic["case"], "boundaries");
        assert_eq!(diagnostic["outcome"], "Exited(1)");
        assert_eq!(diagnostic["truncated"], true);
        assert_eq!(diagnostic["stderr"].as_str().unwrap().len(), DIAGNOSTIC_LIMIT);
        let encoded = diagnostic.to_string();
        assert!(encoded.contains("\\u0000"));
        assert!(!encoded.contains('\0'));
        assert!(!encoded.contains("not-in-diagnostic"));
    }
}
