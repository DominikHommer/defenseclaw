// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Private v1 framing. A binding correlates host records; it grants no authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};

pub const VERSION: u16 = 1;
pub const MAX_FRAME: usize = 256 << 10;
pub const MAX_DATA: usize = 16 << 10;
pub const HOOK_DIRECTORY: &str = "/run/defenseclaw-hook";
pub const HOOK_SOCKET: &str = "/run/defenseclaw-hook/ingress.sock";
pub const HOOK_PROFILE: &str = "/run/defenseclaw-hook/runtime.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolError;

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub session_id: String,
    pub session_digest: String,
    pub policy_digest: String,
    pub runtime_digest: String,
    pub harness_digest: String,
    pub preparation_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Prepare,
    Launch,
    Input,
    InputEof,
    Resize,
    Cancel,
    Wait,
    Destroy,
    Prepared,
    Started,
    Output,
    Exited,
    Destroyed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub version: u16,
    pub sequence: u64,
    pub request: u64,
    pub binding: Binding,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<Preparation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Completion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_token_observation: Option<NativeTokenObservation>,
}

/// Diagnostic-only same-child observation, never endpoint authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTokenObservation {
    pub diagnostic_only: bool,
    pub authorization_granted: bool,
    pub query_complete: bool,
    pub primary_token: bool,
    pub user_sid_valid: bool,
    pub user_matches_peer: bool,
    pub app_container_sid_present: bool,
    pub app_container_sid_valid: bool,
    pub token_is_app_container: bool,
    pub integrity_rid: u32,
    pub token_session_id: u32,
    pub session_matches_peer: bool,
    pub token_handles_closed: bool,
}
impl NativeTokenObservation {
    pub fn validate(&self) -> Result<()> {
        if !self.diagnostic_only
            || self.authorization_granted
            || !self.query_complete
            || !self.primary_token
            || !self.user_sid_valid
            || !self.token_handles_closed
            || self.app_container_sid_present != self.app_container_sid_valid
        {
            return Err(ProtocolError);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub backend: String,
    pub argv: Vec<String>,
    pub environment: Vec<Variable>,
    pub workdir: String,
    pub filesystem: Filesystem,
    pub offline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<Size>,
    pub timeout_ms: u32,
    pub output_limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<Hook>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub session_id: String,
    pub read_index: u16,
    pub profile_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Variable {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Size {
    pub rows: u16,
    pub columns: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Data {
    pub stream: String,
    #[serde(with = "stdio_base64")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub exit_code: i32,
    pub timed_out: bool,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    InvalidRequest,
    Unsupported,
    PreparationFailed,
    LaunchFailed,
    IoFailed,
    CleanupFailed,
}

// Diagnostic-only Windows constructor gates. No string selects authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePreparationStage {
    WindowsCapabilityBinding,
    WindowsCapabilityObjects,
    WindowsInputShape,
    WindowsPayloadAccess,
    WindowsPayloadIdentity,
    WindowsCwdAccess,
    WindowsCwdIdentity,
    WindowsCwdPrivacy,
    WindowsCwdPath,
    WindowsRootPin,
    WindowsGrantAccess,
    WindowsGrantIdentity,
    WindowsGrantPath,
    WindowsGrantPin,
    WindowsPayloadPath,
    WindowsArgvPolicy,
    WindowsPolicyFloor,
    WindowsPayloadCustody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: FailureCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_stage: Option<NativePreparationStage>,
}

fn text(value: &str, limit: usize) -> bool {
    value.len() <= limit && !value.contains('\0')
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(value))
}

fn valid_session(value: &str) -> bool {
    let session = value.as_bytes();
    !session.is_empty()
        && session.len() <= 128
        && session[0].is_ascii_alphanumeric()
        && session
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        if !valid_session(&self.session_id)
            || [
                &self.session_digest,
                &self.policy_digest,
                &self.runtime_digest,
                &self.harness_digest,
                &self.preparation_hash,
            ]
            .into_iter()
            .any(|value| !digest(value))
        {
            return Err(ProtocolError);
        }
        Ok(())
    }
}

fn wire_path(backend: &str, path: &str) -> bool {
    if path.is_empty() || !text(path, 32767) {
        return false;
    }
    if backend == "windows_psec" {
        let bytes = path.as_bytes();
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1..3] == *b":\\"
    } else {
        path.starts_with('/')
    }
}

fn covers_path(ancestor: &str, path: &str) -> bool {
    path == ancestor
        || ancestor == "/" && path.starts_with('/')
        || path
            .strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn protected_grant(path: &str) -> bool {
    ["/proc", "/dev", "/.defenseclaw", HOOK_DIRECTORY]
        .iter()
        .any(|root| covers_path(path, root) || covers_path(root, path))
}

impl Size {
    fn valid(self) -> bool {
        self.rows > 0 && self.columns > 0 && self.rows <= 4096 && self.columns <= 4096
    }
}

impl Preparation {
    pub fn validate(&self) -> Result<()> {
        if !["bubblewrap", "seatbelt", "windows_psec"].contains(&self.backend.as_str())
            || !self.offline
            || self.argv.is_empty()
            || self.argv.len() > 4096
            || !wire_path(&self.backend, &self.argv[0])
            || !wire_path(&self.backend, &self.workdir)
            || self.timeout_ms == 0
            || self.timeout_ms > 24 * 60 * 60 * 1000
            || self.output_limit == 0
            || self.output_limit > 64 << 20
            || self.terminal.is_some_and(|value| !value.valid())
            || self.environment.len() > 256
        {
            return Err(ProtocolError);
        }
        if self.argv.iter().any(|arg| !text(arg, 128 << 10))
            || self.argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > 128 << 10
        {
            return Err(ProtocolError);
        }
        let mut names = HashSet::new();
        let mut bytes = 0;
        for variable in &self.environment {
            let name = variable.name.as_bytes();
            let key = if self.backend == "windows_psec" {
                variable.name.to_ascii_uppercase()
            } else {
                variable.name.clone()
            };
            if name.is_empty()
                || name.len() > 128
                || !(name[0].is_ascii_alphabetic() || name[0] == b'_')
                || !name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
                || !names.insert(key)
                || !text(&variable.value, 32 << 10)
                || ["DEFENSECLAW_HOOK_SESSION", "DEFENSECLAW_HOOK_SOCKET"]
                    .contains(&variable.name.as_str())
            {
                return Err(ProtocolError);
            }
            bytes += name.len() + variable.value.len() + 2;
        }
        if bytes > 64 << 10 {
            return Err(ProtocolError);
        }
        if let Some(hook) = &self.hook {
            if self.backend != "bubblewrap"
                || !valid_session(&hook.session_id)
                || !digest(&hook.profile_digest)
                || self
                    .filesystem
                    .read
                    .get(usize::from(hook.read_index))
                    .map(String::as_str)
                    != Some(HOOK_DIRECTORY)
                || protected_grant(&self.workdir)
            {
                return Err(ProtocolError);
            }
        }
        bytes = 0;
        for (group, paths) in [
            &self.filesystem.read,
            &self.filesystem.write,
            &self.filesystem.deny,
        ]
        .into_iter()
        .enumerate()
        {
            let mut seen = HashSet::new();
            if paths.len() > 256 {
                return Err(ProtocolError);
            }
            for (index, path) in paths.iter().enumerate() {
                let hook_grant = self.hook.as_ref().is_some_and(|hook| {
                    group == 0 && index == usize::from(hook.read_index) && path == HOOK_DIRECTORY
                });
                if !wire_path(&self.backend, path)
                    || !seen.insert(path)
                    || protected_grant(path) && !hook_grant
                {
                    return Err(ProtocolError);
                }
                bytes += path.len() + 1;
            }
        }
        if bytes > 64 << 10 {
            return Err(ProtocolError);
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = b"defenseclaw-mxc-preparation-v1\0".to_vec();
        fn string(bytes: &mut Vec<u8>, value: &str) {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        fn strings(bytes: &mut Vec<u8>, values: &[String]) {
            bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
            for value in values {
                string(bytes, value);
            }
        }
        string(&mut bytes, &self.backend);
        strings(&mut bytes, &self.argv);
        bytes.extend_from_slice(&(self.environment.len() as u32).to_be_bytes());
        for variable in &self.environment {
            string(&mut bytes, &variable.name);
            string(&mut bytes, &variable.value);
        }
        string(&mut bytes, &self.workdir);
        strings(&mut bytes, &self.filesystem.read);
        strings(&mut bytes, &self.filesystem.write);
        strings(&mut bytes, &self.filesystem.deny);
        bytes.push(1);
        match self.terminal {
            None => bytes.push(0),
            Some(size) => {
                bytes.push(1);
                bytes.extend_from_slice(&size.rows.to_be_bytes());
                bytes.extend_from_slice(&size.columns.to_be_bytes());
            }
        }
        bytes.extend_from_slice(&self.timeout_ms.to_be_bytes());
        bytes.extend_from_slice(&self.output_limit.to_be_bytes());
        if let Some(hook) = &self.hook {
            bytes.extend_from_slice(b"\x01defenseclaw-hook-v1\x00");
            string(&mut bytes, &hook.session_id);
            bytes.extend_from_slice(&hook.read_index.to_be_bytes());
            string(&mut bytes, &hook.profile_digest);
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(71);
        encoded.push_str("sha256:");
        for byte in Sha256::digest(bytes).iter().copied() {
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 15)] as char);
        }
        Ok(encoded)
    }
}

impl Frame {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.version != VERSION || self.sequence == 0 || self.request == 0 {
            return Err(ProtocolError);
        }
        if let Some(observation) = &self.native_token_observation {
            if self.kind != Kind::Started {
                return Err(ProtocolError);
            }
            observation.validate()?;
        }
        let payloads = [
            self.plan.is_some(),
            self.data.is_some(),
            self.size.is_some(),
            self.result.is_some(),
            self.failure.is_some(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count();
        match self.kind {
            Kind::Prepare => {
                let plan = self.plan.as_ref().ok_or(ProtocolError)?;
                if payloads != 1
                    || plan.hash()? != self.binding.preparation_hash
                    || plan
                        .hook
                        .as_ref()
                        .is_some_and(|hook| hook.session_id != self.binding.session_id)
                {
                    return Err(ProtocolError);
                }
            }
            Kind::Input | Kind::Output => {
                let data = self.data.as_ref().ok_or(ProtocolError)?;
                if payloads != 1
                    || data.bytes.is_empty()
                    || data.bytes.len() > MAX_DATA
                    || self.kind == Kind::Input && data.stream != "stdin"
                    || self.kind == Kind::Output
                        && !["stdout", "stderr"].contains(&data.stream.as_str())
                {
                    return Err(ProtocolError);
                }
            }
            Kind::Resize => {
                if payloads != 1 || !self.size.ok_or(ProtocolError)?.valid() {
                    return Err(ProtocolError);
                }
            }
            Kind::Exited if payloads == 1 && self.result.is_some() => {}
            Kind::Failed if payloads == 1 && self.failure.is_some() => {
                let failure = self.failure.as_ref().ok_or(ProtocolError)?;
                if failure.native_stage.is_some() && failure.code != FailureCode::PreparationFailed
                {
                    return Err(ProtocolError);
                }
            }
            Kind::Launch
            | Kind::InputEof
            | Kind::Cancel
            | Kind::Wait
            | Kind::Destroy
            | Kind::Prepared
            | Kind::Started
            | Kind::Destroyed
                if payloads == 0 => {}
            _ => return Err(ProtocolError),
        }
        Ok(())
    }
}

pub fn parse(bytes: &[u8]) -> Result<Frame> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME || std::str::from_utf8(bytes).is_err() {
        return Err(ProtocolError);
    }
    // All objects below deserialize into deny_unknown_fields structs. Serde
    // rejects duplicate known fields, malformed strings and unpaired surrogates.
    // Refuse null even for optional fields before their Option deserializer.
    let (mut quoted, mut escaped, mut depth, mut tokens) = (false, false, 0usize, 0usize);
    for (index, byte) in bytes.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                tokens += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                tokens += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(ProtocolError)?;
            }
            b'n' if bytes[index..].starts_with(b"null") => return Err(ProtocolError),
            b',' => tokens += 1,
            _ => {}
        }
        if depth > 25 || tokens > 32768 {
            return Err(ProtocolError);
        }
    }
    let value: Frame = serde_json::from_slice(bytes).map_err(|_| ProtocolError)?;
    value.validate()?;
    Ok(value)
}

pub struct Decoder<R> {
    reader: R,
    poisoned: bool,
}

impl<R: Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            poisoned: false,
        }
    }

    pub fn decode(&mut self) -> Result<Frame> {
        if self.poisoned {
            return Err(ProtocolError);
        }
        let result = (|| {
            let mut header = [0u8; 4];
            self.reader
                .read_exact(&mut header)
                .map_err(|_| ProtocolError)?;
            let size = u32::from_be_bytes(header) as usize;
            if size == 0 || size > MAX_FRAME {
                return Err(ProtocolError);
            }
            let mut bytes = vec![0; size];
            self.reader
                .read_exact(&mut bytes)
                .map_err(|_| ProtocolError)?;
            parse(&bytes)
        })();
        self.poisoned = result.is_err();
        result
    }
}

pub struct Encoder<W> {
    writer: W,
    poisoned: bool,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            poisoned: false,
        }
    }

    pub fn encode(&mut self, frame: &Frame) -> Result<()> {
        if self.poisoned {
            return Err(ProtocolError);
        }
        let result = (|| {
            frame.validate()?;
            let bytes = serde_json::to_vec(frame).map_err(|_| ProtocolError)?;
            if bytes.is_empty() || bytes.len() > MAX_FRAME {
                return Err(ProtocolError);
            }
            self.writer
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .map_err(|_| ProtocolError)?;
            self.writer.write_all(&bytes).map_err(|_| ProtocolError)?;
            self.writer.flush().map_err(|_| ProtocolError)
        })();
        self.poisoned = result.is_err();
        result
    }
}

mod stdio_base64 {
    use base64::{
        Engine, alphabet,
        engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    };
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        let compact: String = value
            .chars()
            .filter(|value| !matches!(*value, '\r' | '\n'))
            .collect();
        // Match Go encoding/json's StdEncoding: CR/LF and unused trailing bits
        // are accepted; output always uses canonical padded StdEncoding.
        let engine = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        );
        let decoded = engine.decode(compact).map_err(serde::de::Error::custom)?;
        if decoded.len() > super::MAX_DATA {
            return Err(serde::de::Error::custom("bounded stdio required"));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Frame {
        let plan = Preparation {
            backend: "bubblewrap".into(),
            argv: [
                "/fixed/bootstrap",
                "",
                "a b",
                "a\"b",
                "λ-雪",
                "tail\\",
                "$HOME;$(fixed)&|<>",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            environment: vec![Variable {
                name: "HOME".into(),
                value: "/fixed/home".into(),
            }],
            workdir: "/fixed/work".into(),
            filesystem: Filesystem {
                read: vec!["/fixed/bootstrap".into()],
                write: vec!["/fixed/work".into()],
                deny: vec![],
            },
            offline: true,
            terminal: Some(Size {
                rows: 30,
                columns: 100,
            }),
            timeout_ms: 30000,
            output_limit: 1 << 20,
            hook: None,
        };
        Frame {
            version: VERSION,
            sequence: 1,
            request: 1,
            binding: Binding {
                session_id: "fixed-session".into(),
                session_digest: format!("sha256:{}", "a".repeat(64)),
                policy_digest: format!("sha256:{}", "b".repeat(64)),
                runtime_digest: format!("sha256:{}", "c".repeat(64)),
                harness_digest: format!("sha256:{}", "d".repeat(64)),
                preparation_hash: plan.hash().unwrap(),
            },
            kind: Kind::Prepare,
            plan: Some(plan),
            data: None,
            size: None,
            result: None,
            failure: None,
            native_token_observation: None,
        }
    }

    #[test]
    fn independent_go_hash_vector_and_no_read_ahead() {
        let frame = fixture();
        assert_eq!(
            frame.binding.preparation_hash,
            "sha256:2b70112993942ea7aecfe3d146550fcda20a7de01f9646e5223e07f637ae9174"
        );
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes).encode(&frame).unwrap();
        let length = bytes.len();
        bytes.extend_from_slice(b"sentinel");
        let mut input = std::io::Cursor::new(bytes);
        assert_eq!(Decoder::new(&mut input).decode().unwrap(), frame);
        assert_eq!(input.position() as usize, length);
    }

    #[test]
    fn typed_hook_is_hash_bound_to_session_and_one_fixed_read_slot() {
        let mut frame = fixture();
        let baseline = frame.binding.preparation_hash.clone();
        let plan = frame.plan.as_mut().unwrap();
        plan.filesystem.read.push(HOOK_DIRECTORY.into());
        plan.hook = Some(Hook {
            session_id: "fixed-session".into(),
            read_index: 1,
            profile_digest: format!("sha256:{}", "a".repeat(64)),
        });
        frame.binding.preparation_hash = plan.hash().unwrap();
        assert_eq!(
            frame.binding.preparation_hash,
            "sha256:8a3ccd0c445a94ebb2b56a4147c9297330fe6d6012167ff845b1fc73a12344db"
        );
        assert_ne!(frame.binding.preparation_hash, baseline);
        frame.validate().unwrap();
        let mut changed = frame.clone();
        changed
            .plan
            .as_mut()
            .unwrap()
            .hook
            .as_mut()
            .unwrap()
            .session_id = "other-session".into();
        changed.binding.preparation_hash = changed.plan.as_ref().unwrap().hash().unwrap();
        assert_eq!(changed.validate(), Err(ProtocolError));
        for path in ["/run", "/", HOOK_SOCKET, "/.defenseclaw/hooks"] {
            let mut changed = frame.clone();
            changed
                .plan
                .as_mut()
                .unwrap()
                .filesystem
                .read
                .push(path.into());
            assert_eq!(
                changed.plan.as_ref().unwrap().validate(),
                Err(ProtocolError)
            );
        }
        let mutations: [fn(&mut Preparation); 2] = [
            |plan: &mut Preparation| plan.filesystem.write.push("/".into()),
            |plan: &mut Preparation| plan.workdir = "/".into(),
        ];
        for mutation in mutations {
            let mut changed = frame.clone();
            mutation(changed.plan.as_mut().unwrap());
            assert_eq!(
                changed.plan.as_ref().unwrap().validate(),
                Err(ProtocolError)
            );
        }
        let mut absent = frame.clone();
        absent.plan.as_mut().unwrap().hook = None;
        assert_eq!(absent.plan.as_ref().unwrap().validate(), Err(ProtocolError));
    }

    #[test]
    fn ambiguous_json_and_null_poison_the_decoder() {
        let mut failure = fixture();
        failure.kind = Kind::Failed;
        failure.plan = None;
        failure.failure = Some(Failure {
            code: FailureCode::PreparationFailed,
            native_stage: None,
        });
        let absent = serde_json::to_vec(&failure).unwrap();
        assert!(
            !std::str::from_utf8(&absent)
                .unwrap()
                .contains("native_stage")
        );
        assert_eq!(parse(&absent).unwrap(), failure);
        failure.failure.as_mut().unwrap().native_stage =
            Some(NativePreparationStage::WindowsCwdPrivacy);
        let diagnostic = serde_json::to_vec(&failure).unwrap();
        assert_eq!(parse(&diagnostic).unwrap(), failure);
        for code in [
            FailureCode::InvalidRequest,
            FailureCode::Unsupported,
            FailureCode::LaunchFailed,
            FailureCode::IoFailed,
            FailureCode::CleanupFailed,
        ] {
            let mut changed = failure.clone();
            changed.failure.as_mut().unwrap().code = code;
            assert_eq!(
                parse(&serde_json::to_vec(&changed).unwrap()),
                Err(ProtocolError)
            );
        }
        for replacement in ["private-unrecognized-stage", "", "WINDOWS_CWD_PRIVACY"] {
            let changed = std::str::from_utf8(&diagnostic)
                .unwrap()
                .replace("windows_cwd_privacy", replacement);
            assert_eq!(parse(changed.as_bytes()), Err(ProtocolError));
        }
        let frame = fixture();
        let original = serde_json::to_string(&frame).unwrap();
        for changed in [
            original.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            original.replacen("\"version\":1", "\"Version\":1", 1),
            original.replacen("\"offline\":true", "\"offline\":null", 1),
            original.replacen("\"rows\":30", "\"rows\":30,\"unknown\":0", 1),
            original.replacen("\"a b\"", "\"a\\ud800b\"", 1),
            original.replacen("\"a b\"", "\"a\\u0000b\"", 1),
            format!("{original} {{}}"),
        ] {
            assert_ne!(changed, original);
            let mut bytes = (changed.len() as u32).to_be_bytes().to_vec();
            bytes.extend(changed.bytes());
            let mut decoder = Decoder::new(std::io::Cursor::new(bytes));
            assert_eq!(decoder.decode(), Err(ProtocolError));
            assert_eq!(decoder.decode(), Err(ProtocolError));
        }
    }

    #[test]
    fn native_token_observation_is_started_only_strict_and_absence_preserves_bytes() {
        let mut frame = fixture();
        frame.kind = Kind::Started;
        frame.plan = None;
        let legacy = serde_json::to_vec(&frame).unwrap();
        assert!(!String::from_utf8_lossy(&legacy).contains("native_token_observation"));
        assert_eq!(parse(&legacy).unwrap(), frame);
        frame.native_token_observation = Some(token_observation_fixture());
        let raw = serde_json::to_vec(&frame).unwrap();
        assert_eq!(parse(&raw).unwrap(), frame);
        for kind in [
            Kind::Prepare,
            Kind::Prepared,
            Kind::Launch,
            Kind::Output,
            Kind::Exited,
            Kind::Failed,
            Kind::Destroyed,
        ] {
            let mut changed = frame.clone();
            changed.kind = kind;
            assert!(changed.validate().is_err());
        }
        let object = serde_json::to_value(frame.native_token_observation.unwrap()).unwrap();
        for key in object.as_object().unwrap().keys() {
            let mut missing = serde_json::to_value(&frame).unwrap();
            missing["native_token_observation"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(parse(&serde_json::to_vec(&missing).unwrap()).is_err());
            let mut null = serde_json::to_value(&frame).unwrap();
            null["native_token_observation"][key.as_str()] = serde_json::Value::Null;
            assert!(parse(&serde_json::to_vec(&null).unwrap()).is_err());
        }
        for (key, value) in [
            ("authorization_granted", serde_json::json!(true)),
            ("query_complete", serde_json::json!(false)),
            ("integrity_rid", serde_json::json!(-1)),
            ("token_session_id", serde_json::json!(4294967296u64)),
            ("sid", serde_json::json!("private")),
        ] {
            let mut changed = serde_json::to_value(&frame).unwrap();
            changed["native_token_observation"][key] = value;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let text = String::from_utf8(raw).unwrap();
        assert!(
            parse(
                text.replace(
                    "\"diagnostic_only\":true",
                    "\"diagnostic_only\":true,\"diagnostic_only\":true"
                )
                .as_bytes()
            )
            .is_err()
        );
        let mut observed = token_observation_fixture();
        observed.user_matches_peer = false;
        observed.session_matches_peer = false;
        observed.token_is_app_container = true;
        observed.integrity_rid = u32::MAX;
        observed.token_session_id = u32::MAX;
        observed.validate().unwrap(); // measurements are not admission policy
    }
}

#[cfg(test)]
pub(crate) fn token_observation_fixture() -> NativeTokenObservation {
    NativeTokenObservation {
        diagnostic_only: true,
        authorization_granted: false,
        query_complete: true,
        primary_token: true,
        user_sid_valid: true,
        user_matches_peer: true,
        app_container_sid_present: false,
        app_container_sid_valid: false,
        token_is_app_container: false,
        integrity_rid: 4096,
        token_session_id: 1,
        session_matches_peer: true,
        token_handles_closed: true,
    }
}
