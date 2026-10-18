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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};

const PREFIX: &str = "dc-axis-windows-psec-";
const SENTINEL: &[u8] = b"fixed-public-synthetic-canary\n";
const LIMIT: u64 = 64 * 1024;

pub fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--fixed-child") {
        return child(&args[1..]);
    }
    ensure!(args.is_empty(), "no command, policy or path arguments are accepted");
    let system = PathBuf::from(std::env::var("SystemRoot")?).canonicalize()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let temp_parent = std::env::temp_dir().canonicalize()?;
    let owned = tempfile::Builder::new().prefix(PREFIX).tempdir_in(&temp_parent)?;
    let root = owned.path().canonicalize()?;
    verify_fixture_root(&root, &temp_parent)?;
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
    let endpoints = Endpoints::new()?;
    let ports = endpoints.ports();
    run_case(&paths, &executable, "boundary", &ports)?;
    endpoints.require_no_contained_delivery()?;
    run_case(&paths, &executable, "exit23", &ports)?;
    run_case(&paths, &executable, "timeout", &ports)?;
    ensure!(fs::read(&paths.outside)? == SENTINEL, "outside canary changed");
    ensure!(fs::read(&paths.readonly)? == SENTINEL, "read-only canary changed");
    // Verify the resolved absolute target before recursive fixture cleanup.
    verify_fixture_root(&root, &temp_parent)?;
    std::env::set_current_dir(&temp_parent)?;
    owned.close().context("remove verified owned fixture after all SDK handles stopped")?;
    ensure!(!root.exists(), "owned fixture remains");
    println!("{}", serde_json::json!({
        "axis_commit": "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
        "mxc_commit": "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2",
        "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
        "backend": "native_windows_psec_only", "production_qualification": false,
        "checks": ["private_environment", "allowed_write", "outside_read_write_denied",
            "readonly_write_denied", "loopback_ipv4_ipv6_tcp_udp", "exit23", "timeout",
            "retained_direct_process_handles_signaled", "owned_fixture_removed"],
        "scope": "fixed offline canaries; no terminal, proxy, credentials, model or general resource audit"
    }));
    Ok(0)
}

fn verify_fixture_root(root: &Path, temp_parent: &Path) -> Result<()> {
    ensure!(root.is_absolute() && root.parent() == Some(temp_parent), "fixture left private temp parent");
    ensure!(root.file_name().and_then(|p| p.to_str()).is_some_and(|p| p.starts_with(PREFIX)), "unexpected fixture identity");
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
            workspace: root.join("workspace"), home: root.join("home"),
            temporary: root.join("tmp"), outside: root.join("outside-parent/outside.txt"),
            outside_parent: root.join("outside-parent"),
            readonly: root.join("readonly.txt"), system: system.into(),
        };
        for directory in [&result.workspace, &result.home, &result.temporary, &result.outside_parent] {
            fs::create_dir(directory)?;
        }
        for directory in [result.home.join("AppData/Roaming"), result.home.join("AppData/Local")] {
            fs::create_dir_all(directory)?;
        }
        fs::write(&result.outside, SENTINEL)?;
        fs::write(&result.readonly, SENTINEL)?;
        fs::write(result.workspace.join("fixture-seal"), SENTINEL)?;
        Ok(result)
    }

    fn environment(&self) -> Vec<(String, String)> {
        [
            ("SYSTEMROOT", self.system.clone()), ("WINDIR", self.system.clone()),
            ("HOME", self.home.clone()), ("USERPROFILE", self.home.clone()),
            ("APPDATA", self.home.join("AppData/Roaming")),
            ("LOCALAPPDATA", self.home.join("AppData/Local")),
            ("TEMP", self.temporary.clone()), ("TMP", self.temporary.clone()),
        ].into_iter().map(|(name, value)| (name.to_owned(), value.to_string_lossy().into_owned())).collect()
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
    ensure!(policy.runtime.provider == RuntimeProvider::Mxc, "MXC required");
    ensure!(matches!(policy.filesystem.compatibility, Compatibility::HardRequirement), "hard filesystem required");
    ensure!(matches!(policy.network.mode, NetworkMode::Block), "offline policy required");
    let quoted = format!("\"{}\"", executable.display());
    ensure!(!executable.to_string_lossy().contains('"'), "invalid executable path");
    let mut request = ContainerRequest::new(format!("{quoted} --fixed-child {mode} {} {} {} {}", ports[0], ports[1], ports[2], ports[3]));
    request.containment = Containment::ProcessContainer(ProcessContainerConfig::default());
    request.filesystem = Some(FilesystemPolicy {
        readwrite_paths: policy.filesystem.read_write.clone(), readonly_paths: policy.filesystem.read_only.clone(),
        denied_paths: policy.filesystem.deny.clone(), clear_policy_on_exit: Some(true),
    });
    request.network = Some(NetworkPolicy {
        egress: Some(NetworkEgressPolicy { default: Some(NetworkAction::Deny), ..Default::default() }),
        ingress: Some(NetworkIngressPolicy { default: Some(NetworkAction::Deny), host_loopback: Some(NetworkAction::Deny) }),
        runtime_config: None,
    });
    request.timeout_ms = Some(u32::try_from(policy.process.timeout_sec.context("explicit timeout required")? * 1000)?);
    request.working_directory = Some(paths.workspace.to_string_lossy().into_owned());
    request.environment = Some(paths.environment());
    request.inherit_default_environment = Some(false);
    let mut process = v1::spawn_windows_psec(request, SpawnOptions { telemetry: Some(TelemetryConfig { enabled: Some(false) }) })?;
    // Hold the actual direct process handle before wait/reap; never signal an inferred PID.
    let observed = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, process.id()) }?;
    let stdout = process.take_stdout().context("stdout pipe missing")?;
    let stderr = process.take_stderr().context("stderr pipe missing")?;
    let out = thread::spawn(move || bounded(stdout));
    let err = thread::spawn(move || bounded(stderr));
    let outcome = process.wait();
    let signaled = unsafe { WaitForSingleObject(observed, 1000) } == WAIT_OBJECT_0;
    unsafe { CloseHandle(observed) }?;
    let output = out.join().map_err(|_| anyhow::anyhow!("stdout reader panic"))??;
    let diagnostics = err.join().map_err(|_| anyhow::anyhow!("stderr reader panic"))??;
    ensure!(signaled, "retained direct process handle is not signaled");
    let outcome = outcome?;
    match mode {
        "boundary" => {
            ensure!(outcome == WaitResult::Exited(0), "boundary failed: {outcome:?}: {output} {diagnostics}");
            ensure!(output.lines().any(|line| line == "FIXED_BOUNDARIES_PASS"), "boundary observations missing");
        }
        "exit23" => {
            ensure!(output.lines().any(|line| line == "FIXED_EXIT23_STARTED"), "exit payload never started");
            ensure!(outcome == WaitResult::Exited(23), "exit status differs: {outcome:?}");
        }
        "timeout" => {
            ensure!(output.lines().any(|line| line == "FIXED_TIMEOUT_STARTED"), "timeout payload never started");
            ensure!(outcome == WaitResult::TimedOut, "typed timeout missing: {outcome:?}");
        }
        _ => bail!("unsupported fixed case"),
    }
    println!("{}", serde_json::json!({"case": mode, "outcome": format!("{outcome:?}"), "direct_handle_signaled": signaled, "stdout": output, "stderr": diagnostics}));
    drop(process);
    Ok(())
}

fn bounded(mut reader: Box<dyn Read + Send>) -> Result<String> {
    let mut bytes = Vec::new();
    reader.by_ref().take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "fixed output exceeded its bound");
    Ok(String::from_utf8(bytes)?)
}

fn child(args: &[String]) -> Result<i32> {
    ensure!(args.len() == 5, "only fixed child mode and four canary ports are accepted");
    match args[0].as_str() {
        "exit23" => { println!("FIXED_EXIT23_STARTED"); return Ok(23); }
        "timeout" => { println!("FIXED_TIMEOUT_STARTED"); thread::sleep(Duration::from_secs(30)); return Ok(44); }
        "boundary" => {}
        _ => bail!("unsupported fixed child"),
    }
    let workspace = std::env::current_dir()?.canonicalize()?;
    ensure!(workspace.file_name().is_some_and(|name| name == "workspace"), "private cwd missing");
    let root = workspace.parent().context("fixture parent missing")?;
    ensure!(root.file_name().and_then(|p| p.to_str()).is_some_and(|p| p.starts_with(PREFIX)), "unexpected fixture root");
    ensure!(fs::read(workspace.join("fixture-seal"))? == SENTINEL, "fixture seal missing");
    for (key, relative) in [("HOME", "home"), ("USERPROFILE", "home"), ("TEMP", "tmp"), ("TMP", "tmp")] {
        ensure!(PathBuf::from(std::env::var(key)?) == root.join(relative), "private {key} differs");
    }
    ensure!(std::env::var_os("OPENAI_API_KEY").is_none() && std::env::var_os("ANTHROPIC_API_KEY").is_none(), "credential environment present");
    ensure!(std::env::var_os("DC_AXIS_INHERIT_CANARY").is_none(), "parent-only inheritance canary reached child");
    fs::write(workspace.join("allowed-write"), b"fixed write")?;
    fs::write(root.join("outside-parent/allowed-sibling"), b"fixed parent-grant write")?;
    ensure!(fs::read(root.join("outside-parent/outside.txt")).is_err_and(permission_denied), "outside read was not denied");
    ensure!(fs::write(root.join("outside-parent/outside.txt"), b"unexpected").is_err_and(permission_denied), "outside write was not denied");
    ensure!(fs::read(root.join("readonly.txt"))? == SENTINEL, "read-only read failed");
    ensure!(fs::write(root.join("readonly.txt"), b"unexpected").is_err_and(permission_denied), "read-only write was not denied");
    let ports: Vec<u16> = args[1..].iter().map(|port| port.parse()).collect::<std::result::Result<_, _>>()?;
    for (ip, port) in [(IpAddr::V4(Ipv4Addr::LOCALHOST), ports[0]), (IpAddr::V6(Ipv6Addr::LOCALHOST), ports[2])] {
        ensure!(TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(1)).is_err_and(permission_denied), "contained TCP connect was not denied");
    }
    for (bind, destination) in [("0.0.0.0:0", format!("127.0.0.1:{}", ports[1])), ("[::]:0", format!("[::1]:{}", ports[3]))] {
        match UdpSocket::bind(bind) {
            Ok(socket) => if let Err(error) = socket.send_to(b"FIXED_CONTAINED_UDP", destination) { ensure!(permission_denied(error), "unexpected UDP error"); },
            Err(error) => ensure!(permission_denied(error), "unexpected UDP bind error"),
        }
    }
    println!("FIXED_BOUNDARIES_PASS");
    Ok(0)
}

fn permission_denied(error: io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(10013)
}

struct Endpoints { tcp4: TcpListener, udp4: UdpSocket, tcp6: TcpListener, udp6: UdpSocket }

impl Endpoints {
    fn new() -> Result<Self> {
        let endpoints = Self { tcp4: TcpListener::bind("127.0.0.1:0")?, udp4: UdpSocket::bind("127.0.0.1:0")?, tcp6: TcpListener::bind("[::1]:0")?, udp6: UdpSocket::bind("[::1]:0")? };
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
            ensure!(&buffer[..size] == b"FIXED_HOST_CONTROL", "host UDP positive control failed");
            socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        }
        Ok(endpoints)
    }

    fn ports(&self) -> [u16; 4] { [self.tcp4.local_addr().unwrap().port(), self.udp4.local_addr().unwrap().port(), self.tcp6.local_addr().unwrap().port(), self.udp6.local_addr().unwrap().port()] }

    fn require_no_contained_delivery(&self) -> Result<()> {
        for listener in [&self.tcp4, &self.tcp6] {
            ensure!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock), "contained TCP delivery observed");
        }
        for socket in [&self.udp4, &self.udp6] {
            let mut buffer = [0; 64];
            ensure!(socket.recv_from(&mut buffer).is_err_and(|error| matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)), "contained UDP delivery observed");
        }
        Ok(())
    }
}
