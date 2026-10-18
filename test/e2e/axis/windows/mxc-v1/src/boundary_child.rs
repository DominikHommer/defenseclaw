// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor payload: std only, no SDK or AXIS imports. It accepts no
// caller executable, script, host credential, destination or filesystem path.
use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SENTINEL: &[u8] = b"fixed-public-synthetic-canary\n";

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("fixed child failed: {error}");
            std::process::exit(1);
        }
    }
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn fixed_io<T>(operation: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), format!("{operation}: {error}")))
}

fn run(args: &[OsString]) -> Result<i32, Box<dyn std::error::Error>> {
    require(
        args.first().is_some_and(|arg| arg == "--fixed-child"),
        "fixed child selector required",
    )?;
    let mode = args.get(1).and_then(|arg| arg.to_str());
    if mode == Some("argv") {
        let expected: Vec<OsString> = [
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
        .map(OsString::from)
        .collect();
        require(args == expected, "literal Windows argv differs")?;
        println!("FIXED_ARGV_PASS");
        return Ok(0);
    }
    require(
        args.len() == 6,
        "only a fixed mode and four canary ports are accepted",
    )?;
    let ports: Vec<u16> = args[2..]
        .iter()
        .map(|port| {
            port.to_str()
                .ok_or_else(|| io::Error::other("invalid canary port encoding"))?
                .parse::<u16>()
                .map_err(io::Error::other)
        })
        .collect::<io::Result<_>>()?;
    require(ports.iter().all(|port| *port != 0), "zero canary port")?;
    match mode {
        Some("exit23") => {
            println!("FIXED_EXIT23_STARTED");
            return Ok(23);
        }
        Some("timeout") => {
            println!("FIXED_TIMEOUT_STARTED");
            thread::sleep(Duration::from_secs(30));
            return Ok(44);
        }
        Some("boundary") => {}
        _ => return Err(io::Error::other("unsupported fixed child mode").into()),
    }
    let cwd = fixed_io("private cwd lookup", std::env::current_dir())?;
    let workspace = fixed_io("private cwd canonicalize", cwd.canonicalize())?;
    require(
        workspace
            .file_name()
            .is_some_and(|name| name == "workspace"),
        "private cwd missing",
    )?;
    let root = workspace
        .parent()
        .ok_or_else(|| io::Error::other("fixture parent missing"))?;
    require(
        root.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("dc-axis-windows-psec-")),
        "unexpected fixture root",
    )?;
    require(
        fixed_io(
            "workspace seal read",
            fs::read(workspace.join("fixture-seal")),
        )? == SENTINEL,
        "fixture seal missing",
    )?;
    for (key, expected) in [
        ("HOME", root.join("home")),
        ("USERPROFILE", root.join("home")),
        ("TEMP", root.join("tmp")),
        ("TMP", root.join("tmp")),
        ("APPDATA", root.join("home").join("AppData").join("Roaming")),
        (
            "LOCALAPPDATA",
            root.join("home").join("AppData").join("Local"),
        ),
    ] {
        require(
            PathBuf::from(
                std::env::var_os(key).ok_or_else(|| io::Error::other("private env missing"))?,
            ) == expected,
            "private environment differs",
        )?;
    }
    require(
        std::env::var_os("OPENAI_API_KEY").is_none()
            && std::env::var_os("ANTHROPIC_API_KEY").is_none(),
        "credential environment present",
    )?;
    require(
        std::env::var_os("DC_AXIS_INHERIT_CANARY").is_none(),
        "parent-only inheritance canary reached child",
    )?;
    fixed_io(
        "workspace permitted write",
        fs::write(workspace.join("allowed-write"), b"fixed write"),
    )?;
    fixed_io(
        "outside-parent permitted sibling write",
        fs::write(
            root.join("outside-parent").join("allowed-sibling"),
            b"fixed parent-grant write",
        ),
    )?;
    let outside = root.join("outside-parent").join("outside.txt");
    require(
        fs::read(&outside).is_err_and(permission_denied),
        "outside read was not denied",
    )?;
    require(
        fs::write(&outside, b"unexpected").is_err_and(permission_denied),
        "outside write was not denied",
    )?;
    require(
        fs::read(root.join("readonly.txt"))? == SENTINEL,
        "read-only read failed",
    )?;
    require(
        fs::write(root.join("readonly.txt"), b"unexpected").is_err_and(permission_denied),
        "read-only write was not denied",
    )?;
    for (ip, port) in [
        (IpAddr::V4(Ipv4Addr::LOCALHOST), ports[0]),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), ports[2]),
    ] {
        require(
            TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(1))
                .is_err_and(permission_denied),
            "contained TCP connect was not denied",
        )?;
    }
    for (bind, destination) in [
        ("0.0.0.0:0", format!("127.0.0.1:{}", ports[1])),
        ("[::]:0", format!("[::1]:{}", ports[3])),
    ] {
        match UdpSocket::bind(bind) {
            Ok(socket) => {
                if let Err(error) = socket.send_to(b"FIXED_CONTAINED_UDP", destination) {
                    require(permission_denied(error), "unexpected UDP error")?;
                }
            }
            Err(error) => require(permission_denied(error), "unexpected UDP bind error")?,
        }
    }
    println!("FIXED_BOUNDARIES_PASS");
    Ok(0)
}

fn permission_denied(error: io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(10013)
}
