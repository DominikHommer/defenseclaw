// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Fixed unadmitted diagnostic entry. No customer route, endpoint or fallback.
//! ConPTY has one merged console output stream: the stderr slot is a distinct
//! deliberately closed empty pipe, never a separate guest stderr observation.
use crate::owner::{Engine, Pipes, Prepared, Process};
use crate::windows::WindowsEngine;
use crate::windows_bootstrap::Capabilities;
use crate::windows_io::Pipe;
use crate::wire::{NativeTokenObservation, Preparation, ProtocolError, Result, Size};
use mxc_sdk::v1::{
    OwnedPsecProcess, OwnedWindowsDiagnosticCase as Case, OwnedWindowsDiagnosticFailure,
    OwnedWindowsDiagnosticIo, OwnedWindowsStdio, OwnedWindowsTerminal, PreparedOwnedWindowsPsec,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

#[derive(Clone)]
pub struct Report(Rc<RefCell<Facts>>);
struct Facts {
    case: Case,
    failure: Option<(u8, Option<OwnedWindowsDiagnosticFailure>)>,
    resumed: bool,
    resized: bool,
    root_job_empty: bool,
}
impl Report {
    pub fn new(case: Case) -> Self {
        Self(Rc::new(RefCell::new(Facts {
            case,
            failure: None,
            resumed: false,
            resized: false,
            root_job_empty: false,
        })))
    }
    fn fail(&self, stage: u8, native: Option<OwnedWindowsDiagnosticFailure>) {
        let mut facts = self.0.borrow_mut();
        if facts.failure.is_none() {
            facts.failure = Some((stage, native));
        }
    }
    pub fn protocol_failed(&self) {
        self.fail(7, None);
    }
    /// Closed line for a future explicitly admitted diagnostic harness only.
    /// Creation/Resume alone cannot satisfy that harness's console I/O, resize,
    /// cancel, root+Job0, EOF and Destroyed requirements.
    pub fn summary(&self) -> String {
        let facts = self.0.borrow();
        let (failure, native) = facts.failure.unwrap_or((0, None));
        let native_stage = native.map_or(0, |value| value.stage as u8 + 1);
        let hresult = native
            .and_then(|value| value.hresult)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".into());
        let win32 = native
            .and_then(|value| value.win32)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".into());
        let status = native
            .and_then(|value| value.nt_status)
            .map(|v| format!("{v:08x}"))
            .unwrap_or_else(|| "none".into());
        format!(
            "axis_conpty_diagnostic case={} failure={} native_stage={} hresult={} win32={} ntstatus={} resumed={} resized={} root_job_empty={} diagnostic_only=true authorization_granted=false\n",
            case_name(facts.case),
            failure,
            native_stage,
            hresult,
            win32,
            status,
            facts.resumed,
            facts.resized,
            facts.root_job_empty
        )
    }
}
pub fn case_name(case: Case) -> &'static str {
    match case {
        Case::OrdinaryConpty => "ordinary_conpty",
        Case::HeadlessPsec => "headless_psec",
        Case::ConptyPsec => "conpty_psec",
    }
}
pub fn parse_case(value: &str) -> Result<Case> {
    match value {
        "ordinary_conpty" => Ok(Case::OrdinaryConpty),
        "headless_psec" => Ok(Case::HeadlessPsec),
        "conpty_psec" => Ok(Case::ConptyPsec),
        _ => Err(ProtocolError),
    }
}
fn fixed_shape(case: Case, plan: &Preparation) -> bool {
    plan.backend == "windows_psec"
        && plan.offline
        && plan.hook.is_none()
        && plan.argv.len() == 2
        && plan.argv[1]
            == if case.uses_conpty() {
                "--fixed-console"
            } else {
                "--fixed-headless"
            }
        && plan.timeout_ms == 8000
        && plan.output_limit == 16384
        && plan.terminal
            == if case.uses_conpty() {
                Some(Size {
                    rows: 24,
                    columns: 80,
                })
            } else {
                None
            }
}
pub struct DiagnosticEngine {
    engine: WindowsEngine,
    case: Case,
    report: Report,
}
impl DiagnosticEngine {
    pub fn new(capabilities: Capabilities, case: Case, report: Report) -> Self {
        Self {
            engine: WindowsEngine::new(capabilities),
            case,
            report,
        }
    }
}
impl Engine for DiagnosticEngine {
    fn prepare(&mut self, plan: &Preparation) -> Result<Box<dyn Prepared>> {
        if !fixed_shape(self.case, plan) {
            self.report.fail(1, None);
            return Err(ProtocolError);
        }
        let prepared = self.engine.prepare_owned(plan, true).map_err(|_| {
            self.report.fail(2, None);
            ProtocolError
        })?;
        Ok(Box::new(DiagnosticPrepared {
            prepared,
            case: self.case,
            report: self.report.clone(),
        }))
    }
}
struct DiagnosticPrepared {
    prepared: PreparedOwnedWindowsPsec,
    case: Case,
    report: Report,
}
struct DiagnosticProcess {
    process: OwnedPsecProcess,
    pipes: Option<Pipes>,
    observation: Option<NativeTokenObservation>,
    case: Case,
    report: Report,
}
impl Prepared for DiagnosticPrepared {
    fn launch(self: Box<Self>) -> Result<Box<dyn Process>> {
        let Self {
            prepared,
            case,
            report,
        } = *self;
        let result = (|| -> std::io::Result<(OwnedPsecProcess, Pipes)> {
            let (input, child_input) = Pipe::workload_pair(true)?;
            let (output, child_output) = Pipe::workload_pair(false)?;
            let (error, child_error) = Pipe::workload_pair(false)?;
            let io = if case.uses_conpty() {
                // No synchronous stdio wrappers or worker readers are created.
                drop(child_error); // only an empty transport stderr slot
                OwnedWindowsDiagnosticIo::Terminal(OwnedWindowsTerminal::new(
                    24,
                    80,
                    child_input,
                    child_output,
                )?)
            } else {
                OwnedWindowsDiagnosticIo::Headless(OwnedWindowsStdio::new(
                    child_input,
                    child_output,
                    child_error,
                )?)
            };
            let process = prepared.spawn_diagnostic_suspended(case, io)?;
            // Return immediately after spawn; no callback or pipe validation
            // can lose this successfully created suspended process before Owner.
            Ok((
                process,
                Pipes {
                    input: Some(input),
                    output: Some(output),
                    error: Some(error),
                },
            ))
        })();
        let (process, pipes) = result.map_err(|error| {
            report.fail(3, OwnedWindowsDiagnosticFailure::from_error(&error));
            ProtocolError
        })?;
        Ok(Box::new(DiagnosticProcess {
            process,
            pipes: Some(pipes),
            observation: None,
            case,
            report,
        }))
    }
}
fn token_matches(case: Case, facts: &NativeTokenObservation) -> bool {
    facts.validate().is_ok()
        && facts.user_matches_peer
        && facts.session_matches_peer
        && (case.uses_psec() || (!facts.token_is_app_container && !facts.app_container_sid_present))
}
impl Process for DiagnosticProcess {
    fn take_pipes(&mut self) -> Result<Pipes> {
        self.pipes.take().ok_or(ProtocolError)
    }
    fn finish_launch(&mut self, deadline: Instant) -> Result<()> {
        self.process
            .finish_diagnostic_console_attach()
            .map_err(|error| {
                self.report
                    .fail(4, OwnedWindowsDiagnosticFailure::from_error(&error));
                ProtocolError
            })?;
        let mut observation = None;
        let case = self.case;
        self.process
            .admit_and_resume(
                || {
                    if Instant::now() < deadline {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("fixed diagnostic owner expired"))
                    }
                },
                |child| {
                    let facts = crate::windows_token_probe::query_pre_resume(child)
                        .map_err(|_| std::io::Error::other("fixed diagnostic token refused"))?;
                    if !token_matches(case, &facts) {
                        return Err(std::io::Error::other(
                            "fixed diagnostic child identity differs",
                        ));
                    }
                    observation = Some(facts);
                    Ok(())
                },
                || {}, // no endpoint exists; never reuse for hook admission
            )
            .map_err(|_| {
                self.report.fail(5, None);
                ProtocolError
            })?;
        self.observation = observation;
        self.report.0.borrow_mut().resumed = true;
        Ok(())
    }
    fn native_token_observation(&self) -> Option<NativeTokenObservation> {
        self.observation
    }
    fn resize(&mut self, size: Size) -> Result<()> {
        if !self.case.uses_conpty()
            || size
                != (Size {
                    rows: 31,
                    columns: 97,
                })
        {
            return Err(ProtocolError);
        }
        self.process
            .resize_diagnostic_console(size.rows, size.columns)
            .map_err(|error| {
                self.report
                    .fail(6, OwnedWindowsDiagnosticFailure::from_error(&error));
                ProtocolError
            })?;
        self.report.0.borrow_mut().resized = true;
        Ok(())
    }
    fn try_wait(&mut self) -> Result<Option<i32>> {
        let status = self.process.try_wait().map_err(|_| ProtocolError)?;
        if status.is_some() {
            self.report.0.borrow_mut().root_job_empty = true;
        }
        Ok(status)
    }
    fn stop(&mut self) -> Result<()> {
        self.process.stop().map_err(|_| ProtocolError)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_selector_has_three_exact_cases_without_fallback() {
        for case in [Case::OrdinaryConpty, Case::HeadlessPsec, Case::ConptyPsec] {
            assert_eq!(parse_case(case_name(case)).unwrap(), case);
        }
        for value in [
            "",
            "auto",
            "psec",
            "Ordinary_conpty",
            "conpty_psec ",
            "ordinary_conpty\0",
        ] {
            assert!(parse_case(value).is_err());
        }
    }
    fn plan() -> Preparation {
        Preparation {
            backend: "windows_psec".into(),
            argv: vec!["C:\\fixed\\payload.exe".into(), "--fixed-console".into()],
            environment: vec![],
            workdir: "C:\\fixed\\work".into(),
            filesystem: crate::wire::Filesystem {
                read: vec![],
                write: vec![],
                deny: vec![],
            },
            offline: true,
            terminal: Some(Size {
                rows: 24,
                columns: 80,
            }),
            timeout_ms: 8000,
            output_limit: 16384,
            hook: None,
        }
    }
    #[test]
    fn console_case_shape_binds_terminal_control_and_fixed_argv_before_prepare() {
        let baseline = plan();
        assert!(fixed_shape(Case::ConptyPsec, &baseline));
        assert!(fixed_shape(Case::OrdinaryConpty, &baseline));
        assert!(!fixed_shape(Case::HeadlessPsec, &baseline));
        let mut headless = baseline.clone();
        headless.terminal = None;
        headless.argv[1] = "--fixed-headless".into();
        assert!(fixed_shape(Case::HeadlessPsec, &headless));
        assert!(!fixed_shape(Case::ConptyPsec, &headless));
        for which in 0..8 {
            let mut changed = baseline.clone();
            match which {
                0 => changed.backend = "bubblewrap".into(),
                1 => changed.offline = false,
                2 => changed.argv.push("extra".into()),
                3 => changed.argv[1] = "--arbitrary-command".into(),
                4 => changed.terminal = None,
                5 => {
                    changed.terminal = Some(Size {
                        rows: 31,
                        columns: 97,
                    })
                }
                6 => changed.timeout_ms += 1,
                _ => changed.output_limit += 1,
            }
            assert!(!fixed_shape(Case::ConptyPsec, &changed));
        }
        let mut hook = baseline;
        hook.hook = Some(crate::wire::Hook {
            session_id: "fixed".into(),
            read_index: 0,
            profile_digest: "fixed".into(),
        });
        assert!(!fixed_shape(Case::ConptyPsec, &hook));
    }
    #[test]
    fn console_token_observation_cannot_admit_a_different_user_or_session() {
        let baseline = NativeTokenObservation {
            diagnostic_only: true,
            authorization_granted: false,
            query_complete: true,
            primary_token: true,
            user_sid_valid: true,
            user_matches_peer: true,
            app_container_sid_present: false,
            app_container_sid_valid: false,
            token_is_app_container: false,
            integrity_rid: 8192,
            token_session_id: 1,
            session_matches_peer: true,
            token_handles_closed: true,
        };
        for case in [Case::OrdinaryConpty, Case::HeadlessPsec, Case::ConptyPsec] {
            assert!(token_matches(case, &baseline));
            for which in 0..4 {
                let mut changed = baseline;
                match which {
                    0 => changed.user_matches_peer = false,
                    1 => changed.session_matches_peer = false,
                    2 => changed.token_handles_closed = false,
                    _ => changed.authorization_granted = true,
                }
                assert!(!token_matches(case, &changed));
            }
        }
        let mut container = baseline;
        container.app_container_sid_present = true;
        container.app_container_sid_valid = true;
        container.token_is_app_container = true;
        assert!(!token_matches(Case::OrdinaryConpty, &container));
        assert!(token_matches(Case::ConptyPsec, &container));
    }
    #[test]
    fn console_report_is_closed_and_first_failure_is_sticky() {
        let report = Report::new(Case::ConptyPsec);
        let initial = report.summary();
        assert!(initial.contains("resumed=false resized=false root_job_empty=false"));
        assert!(initial.ends_with("diagnostic_only=true authorization_granted=false\n"));
        report.fail(3, None);
        report.fail(7, None);
        assert!(report.summary().contains("failure=3 native_stage=0"));
    }
}

/// Separate binary only. The ordinary peer's entry and argument contract stay
/// byte-identical. Empty peer env and non-elevated primary token remain floors.
pub fn entry() {
    use crate::owner::Owner;
    use crate::transport::Transport;
    use crate::windows_bootstrap::Prefix;
    use crate::windows_io::wait_handles;
    use std::io::{self, Write};
    use std::time::Duration;
    let mut diagnostic = match Pipe::standard((-12i32) as u32, true) {
        Ok(pipe) => pipe,
        Err(_) => std::process::exit(1),
    };
    let mut report = None;
    let outcome = (|| {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 2
            || args[0] != "defenseclaw-axis-conpty-diagnostic"
            || std::env::vars_os().next().is_some()
        {
            return Err(());
        }
        let case = parse_case(args[1].to_str().ok_or(())?).map_err(|_| ())?;
        let current = Report::new(case);
        report = Some(current.clone());
        crate::windows_token_probe::diagnostic_non_elevated().map_err(|_| ())?;
        let mut input = Pipe::standard((-10i32) as u32, false).map_err(|_| ())?;
        let output = Pipe::standard((-11i32) as u32, true).map_err(|_| ())?;
        let capabilities = Prefix::receive(&mut input, Instant::now() + Duration::from_secs(5))
            .and_then(Prefix::adopt)
            .map_err(|_| ())?;
        let transport = Transport::new(input, output).map_err(|_| ())?;
        Owner::new(
            DiagnosticEngine::new(capabilities, case, current.clone()),
            transport,
        )
        .run()
        .map_err(|_| {
            current.protocol_failed();
            ()
        })
    })();
    let refused = report
        .as_ref()
        .is_some_and(|value| value.0.borrow().failure.is_some());
    let text = report.map_or_else(
        || "axis_conpty_diagnostic preflight_refused\n".to_owned(),
        |value| value.summary(),
    );
    let limit = Instant::now() + Duration::from_millis(100);
    let mut offset = 0;
    while offset < text.len() && Instant::now() < limit {
        match diagnostic.write(&text.as_bytes()[offset..]) {
            Ok(0) => break,
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let events: Vec<_> = diagnostic.wait_handle().into_iter().collect();
                if wait_handles(&events, Duration::from_millis(1)).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let closed = diagnostic
        .close(Instant::now() + Duration::from_millis(500))
        .is_ok();
    if outcome.is_err() || refused || offset != text.len() || !closed {
        std::process::exit(1);
    }
}
