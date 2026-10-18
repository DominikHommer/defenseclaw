// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use axis_core::policy::{Compatibility, NetworkMode, Policy, RuntimeProvider};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, SpawnOptions, TelemetryConfig, WaitResult,
    configs::ProcessContainerConfig,
};
use std::fs;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};

const PREFIX: &str = "dc-axis-windows-psec-";
const SENTINEL: &[u8] = b"fixed-public-synthetic-canary\n";
const LIMIT: u64 = 64 * 1024;

pub fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let loader_only = args.as_slice() == ["--loader-only"];
    ensure!(
        args.is_empty() || loader_only,
        "only the fixed --loader-only diagnostic selector is accepted"
    );
    let system = PathBuf::from(std::env::var("SystemRoot")?).canonicalize()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let temp_parent = std::env::temp_dir().canonicalize()?;
    let owned = tempfile::Builder::new()
        .prefix(PREFIX)
        .tempdir_in(&temp_parent)?;
    // Errors must preserve fixtures, including a failed Job-empty proof. Only
    // the explicit success path below may remove this known owned directory.
    let root = owned.keep().canonicalize()?;
    verify_fixture_root(&root, &temp_parent)?;
    eprintln!("owned contributor fixture: {}", root.display());
    let paths = Paths::create(&root, &system)?;
    // This synchronous entry point has not started threads or called the SDK.
    // Remove raw caller secrets and overrides before either becomes possible.
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    // SAFETY: process environment mutation is confined to this pre-thread stage.
    unsafe {
        for name in names {
            std::env::remove_var(name);
        }
        for (name, value) in paths.environment() {
            std::env::set_var(name, value);
        }
        std::env::set_var("DC_AXIS_INHERIT_CANARY", "fixed-public");
    }
    std::env::set_current_dir(&paths.workspace)?;
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(20));
        eprintln!("fixed contributor supervisor deadline exceeded");
        std::process::exit(124);
    });
    if loader_only {
        let payload = executable
            .with_file_name("defenseclaw-axis-windows-psec-loader-child.exe")
            .canonicalize()?;
        run_case(&paths, &payload, "loader", &[0; 4])?;
    } else {
        let payload = executable
            .with_file_name("defenseclaw-axis-windows-psec-boundary-child.exe")
            .canonicalize()?;
        let endpoints = Endpoints::new()?;
        let ports = endpoints.ports();
        run_case(&paths, &payload, "argv", &ports)?;
        run_case(&paths, &payload, "boundary", &ports)?;
        endpoints.require_no_contained_delivery()?;
        run_case(&paths, &payload, "exit23", &ports)?;
        run_case(&paths, &payload, "timeout", &ports)?;
    }
    ensure!(
        fs::read(&paths.outside)? == SENTINEL,
        "outside canary changed"
    );
    ensure!(
        fs::read(&paths.readonly)? == SENTINEL,
        "read-only canary changed"
    );
    // Verify the resolved absolute target before recursive fixture cleanup.
    verify_fixture_root(&root, &temp_parent)?;
    std::env::set_current_dir(&temp_parent)?;
    fs::remove_dir_all(&root)
        .context("remove verified owned fixture after all SDK handles stopped")?;
    ensure!(!root.exists(), "owned fixture remains");
    let checks = if loader_only {
        vec![
            "separate_std_loader_marker",
            "exit23",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    } else {
        vec![
            "literal_windows_argv",
            "private_environment",
            "allowed_write",
            "outside_read_write_denied",
            "readonly_write_denied",
            "loopback_ipv4_ipv6_tcp_udp",
            "exit23",
            "timeout",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    };
    println!(
        "{}",
        serde_json::json!({
            "axis_commit": "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
            "mxc_commit": "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2",
            "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
            "backend": "native_windows_psec_only", "production_qualification": false,
            "loader_only_diagnostic": loader_only, "checks": checks,
            "scope": if loader_only { "separate std loader marker and exit23 only; no boundary, network or customer qualification" }
                else { "fixed offline canaries; no terminal, proxy, credentials, model or general resource audit" }
        })
    );
    Ok(0)
}

fn verify_fixture_root(root: &Path, temp_parent: &Path) -> Result<()> {
    ensure!(
        root.is_absolute() && root.parent() == Some(temp_parent),
        "fixture left private temp parent"
    );
    ensure!(
        root.file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with(PREFIX)),
        "unexpected fixture identity"
    );
    Ok(())
}

struct Paths {
    workspace: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    outside: PathBuf,
    outside_parent: PathBuf,
    readonly: PathBuf,
    system: PathBuf,
}

impl Paths {
    fn create(root: &Path, system: &Path) -> Result<Self> {
        let result = Self {
            workspace: root.join("workspace"),
            home: root.join("home"),
            temporary: root.join("tmp"),
            outside: root.join("outside-parent").join("outside.txt"),
            outside_parent: root.join("outside-parent"),
            readonly: root.join("readonly.txt"),
            system: system.into(),
        };
        for directory in [
            &result.workspace,
            &result.home,
            &result.temporary,
            &result.outside_parent,
        ] {
            fs::create_dir(directory)?;
        }
        for directory in [
            result.home.join("AppData").join("Roaming"),
            result.home.join("AppData").join("Local"),
        ] {
            fs::create_dir_all(directory)?;
        }
        fs::write(&result.outside, SENTINEL)?;
        fs::write(&result.readonly, SENTINEL)?;
        fs::write(result.workspace.join("fixture-seal"), SENTINEL)?;
        Ok(result)
    }

    fn environment(&self) -> Vec<(String, String)> {
        [
            ("SYSTEMROOT", self.system.clone()),
            ("WINDIR", self.system.clone()),
            ("HOME", self.home.clone()),
            ("USERPROFILE", self.home.clone()),
            ("APPDATA", self.home.join("AppData").join("Roaming")),
            ("LOCALAPPDATA", self.home.join("AppData").join("Local")),
            ("TEMP", self.temporary.clone()),
            ("TMP", self.temporary.clone()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_string_lossy().into_owned()))
        .collect()
    }

    fn policy(&self, executable: &Path, timeout: u64) -> Result<Policy> {
        let value = serde_json::json!({
            "version": 1, "name": "dc-windows-psec-fixed",
            "runtime": {"containment": "process", "provider": "mxc"},
            "filesystem": {"compatibility": "hard_requirement",
                "read_only": [executable, &self.readonly],
                "read_write": [&self.workspace, &self.home, &self.temporary, &self.outside_parent],
                "deny": [&self.outside]},
            "process": {"max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0,
                "identity": "backend_default", "child_processes": "allow", "timeout_sec": timeout},
            "network": {"mode": "block"}
        });
        Policy::from_yaml(&serde_json::to_string(&value)?).context("AXIS fixed policy validation")
    }
}

fn run_case(paths: &Paths, executable: &Path, mode: &str, ports: &[u16; 4]) -> Result<()> {
    let policy = paths.policy(executable, if mode == "timeout" { 1 } else { 5 })?;
    ensure!(
        policy.runtime.provider == RuntimeProvider::Mxc,
        "MXC required"
    );
    ensure!(
        matches!(
            policy.filesystem.compatibility,
            Compatibility::HardRequirement
        ),
        "hard filesystem required"
    );
    ensure!(
        matches!(policy.network.mode, NetworkMode::Block),
        "offline policy required"
    );
    let mut argv = vec![executable.as_os_str().to_owned()];
    if mode == "argv" {
        argv.extend(
            [
                "--fixed-child",
                "argv",
                "",
                "a b",
                "a\"b",
                "tail\\",
                "λ-雪;$()`&|<>*?",
                "quoted space\\",
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        );
    } else if mode != "loader" {
        argv.extend(
            ["--fixed-child", mode]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        argv.extend(
            ports
                .iter()
                .map(|port| std::ffi::OsString::from(port.to_string())),
        );
    }
    let mut request = ContainerRequest::new("");
    request.containment = Containment::ProcessContainer(ProcessContainerConfig::default());
    request.filesystem = Some(FilesystemPolicy {
        readwrite_paths: policy.filesystem.read_write.clone(),
        readonly_paths: policy.filesystem.read_only.clone(),
        denied_paths: policy.filesystem.deny.clone(),
        clear_policy_on_exit: Some(true),
    });
    request.network = Some(NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    });
    request.timeout_ms = Some(u32::try_from(
        policy
            .process
            .timeout_sec
            .context("explicit timeout required")?
            * 1000,
    )?);
    request.working_directory = Some(paths.workspace.to_string_lossy().into_owned());
    request.environment = Some(paths.environment());
    request.inherit_default_environment = Some(false);
    let mut process = v1::spawn_windows_psec_argv(
        request,
        argv,
        SpawnOptions {
            telemetry: Some(TelemetryConfig {
                enabled: Some(false),
            }),
        },
    )?;
    // Hold the actual direct process handle before wait/reap; never signal an inferred PID.
    let observed = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, process.id()) }?;
    // SAFETY: OpenProcess returned a new owned handle. Transfer it immediately
    // so early pipe/wait errors close it once; never adopt the SDK's handle.
    let observed = unsafe { OwnedHandle::from_raw_handle(observed.0) };
    let stdout = process.take_stdout().context("stdout pipe missing")?;
    let stderr = process.take_stderr().context("stderr pipe missing")?;
    let out = thread::spawn(move || bounded(stdout));
    let err = thread::spawn(move || bounded(stderr));
    let outcome = process.wait();
    let signaled =
        unsafe { WaitForSingleObject(HANDLE(observed.as_raw_handle()), 1000) } == WAIT_OBJECT_0;
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panic"))??;
    let diagnostics = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panic"))??;
    ensure!(signaled, "retained direct process handle is not signaled");
    let outcome = outcome?;
    match mode {
        "argv" => {
            ensure!(
                output == "FIXED_ARGV_PASS\n",
                "literal argv marker missing: {output:?} {diagnostics}"
            );
            ensure!(
                outcome == WaitResult::Exited(0),
                "literal argv case differs: {outcome:?}"
            );
        }
        "loader" => {
            ensure!(
                output == "FIXED_PSEC_LOADER_STARTED\n",
                "separate loader marker missing: {output:?} {diagnostics}"
            );
            ensure!(
                outcome == WaitResult::Exited(23),
                "separate loader exit differs: {outcome:?}"
            );
        }
        "boundary" => {
            ensure!(
                outcome == WaitResult::Exited(0),
                "boundary failed: {outcome:?}: {output} {diagnostics}"
            );
            ensure!(
                output.lines().any(|line| line == "FIXED_BOUNDARIES_PASS"),
                "boundary observations missing"
            );
        }
        "exit23" => {
            ensure!(
                output.lines().any(|line| line == "FIXED_EXIT23_STARTED"),
                "exit payload never started"
            );
            ensure!(
                outcome == WaitResult::Exited(23),
                "exit status differs: {outcome:?}"
            );
        }
        "timeout" => {
            ensure!(
                output.lines().any(|line| line == "FIXED_TIMEOUT_STARTED"),
                "timeout payload never started"
            );
            ensure!(
                outcome == WaitResult::TimedOut,
                "typed timeout missing: {outcome:?}"
            );
        }
        _ => bail!("unsupported fixed case"),
    }
    println!(
        "{}",
        serde_json::json!({"case": mode, "outcome": format!("{outcome:?}"), "direct_handle_signaled": signaled, "stdout": output, "stderr": diagnostics})
    );
    drop(process);
    Ok(())
}

fn bounded(mut reader: Box<dyn Read + Send>) -> Result<String> {
    let mut bytes = Vec::new();
    reader.by_ref().take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "fixed output exceeded its bound"
    );
    Ok(String::from_utf8(bytes)?)
}

struct Endpoints {
    tcp4: TcpListener,
    udp4: UdpSocket,
    tcp6: TcpListener,
    udp6: UdpSocket,
}

impl Endpoints {
    fn new() -> Result<Self> {
        let endpoints = Self {
            tcp4: TcpListener::bind("127.0.0.1:0")?,
            udp4: UdpSocket::bind("127.0.0.1:0")?,
            tcp6: TcpListener::bind("[::1]:0")?,
            udp6: UdpSocket::bind("[::1]:0")?,
        };
        for listener in [&endpoints.tcp4, &endpoints.tcp6] {
            let _control = TcpStream::connect(listener.local_addr()?)?;
            let _accepted = listener.accept()?;
            listener.set_nonblocking(true)?;
        }
        for socket in [&endpoints.udp4, &endpoints.udp6] {
            let address = socket.local_addr()?;
            let sender = UdpSocket::bind(SocketAddr::new(address.ip(), 0))?;
            sender.send_to(b"FIXED_HOST_CONTROL", address)?;
            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
            let mut buffer = [0; 64];
            let (size, _) = socket.recv_from(&mut buffer)?;
            ensure!(
                &buffer[..size] == b"FIXED_HOST_CONTROL",
                "host UDP positive control failed"
            );
            socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        }
        Ok(endpoints)
    }

    fn ports(&self) -> [u16; 4] {
        [
            self.tcp4.local_addr().unwrap().port(),
            self.udp4.local_addr().unwrap().port(),
            self.tcp6.local_addr().unwrap().port(),
            self.udp6.local_addr().unwrap().port(),
        ]
    }

    fn require_no_contained_delivery(&self) -> Result<()> {
        for listener in [&self.tcp4, &self.tcp6] {
            ensure!(
                listener
                    .accept()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
                "contained TCP delivery observed"
            );
        }
        for socket in [&self.udp4, &self.udp6] {
            let mut buffer = [0; 64];
            ensure!(
                socket.recv_from(&mut buffer).is_err_and(|error| matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                )),
                "contained UDP delivery observed"
            );
        }
        Ok(())
    }
}
