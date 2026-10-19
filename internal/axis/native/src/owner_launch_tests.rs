// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Calls {
    dropped: usize,
    resumed: usize,
    stopped: usize,
    waited: usize,
    terminal: bool,
    stop_refuses: bool,
    deadline: Option<Instant>,
}
struct Pending(Arc<Mutex<Calls>>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.lock().unwrap().dropped += 1;
    }
}
impl Process for Pending {
    fn take_pipes(&mut self) -> Result<Pipes> {
        Err(ProtocolError)
    }
    fn finish_launch(&mut self, deadline: Instant) -> Result<()> {
        {
            let mut calls = self.0.lock().unwrap();
            calls.resumed += 1;
            calls.deadline = Some(deadline);
        }
        Err(ProtocolError)
    }
    fn stop(&mut self) -> Result<()> {
        let mut c = self.0.lock().unwrap();
        c.stopped += 1;
        if c.stop_refuses {
            Err(ProtocolError)
        } else {
            Ok(())
        }
    }
    fn try_wait(&mut self) -> Result<Option<i32>> {
        let mut c = self.0.lock().unwrap();
        c.waited += 1;
        Ok(c.terminal.then_some(1))
    }
}
fn retained(calls: &Arc<Mutex<Calls>>, now: Instant) -> Active {
    let plan = Preparation {
        backend: "windows_psec".into(),
        argv: vec![],
        environment: vec![],
        workdir: String::new(),
        filesystem: crate::wire::Filesystem {
            read: vec![],
            write: vec![],
            deny: vec![],
        },
        offline: true,
        terminal: None,
        timeout_ms: 1000,
        output_limit: 1024,
        hook: None,
    };
    Active::retained(Box::new(Pending(calls.clone())), &plan, now)
}
#[test]
fn pending_pipe_refusal_retains_process_until_terminal_observation() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let now = Instant::now();
    let mut active = retained(&calls, now);
    assert!(active.activate(now + CONTROL_IDLE).is_err());
    assert_eq!(calls.lock().unwrap().resumed, 0);
    assert_eq!(calls.lock().unwrap().dropped, 0);
    active.stop(now, false).unwrap();
    active.tick(now).unwrap();
    assert!(!active.complete());
    assert_eq!(calls.lock().unwrap().dropped, 0);
    calls.lock().unwrap().terminal = true;
    active.tick(now).unwrap();
    assert!(active.complete());
    assert_eq!(calls.lock().unwrap().waited, 2);
    drop(active);
    assert_eq!(calls.lock().unwrap().dropped, 1);
}
#[test]
fn callback_and_stop_refusal_leave_the_same_pending_process_owned() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let now = Instant::now();
    let mut active = retained(&calls, now);
    assert!(active.finish_launch(now + CONTROL_IDLE).is_err());
    assert_eq!(calls.lock().unwrap().resumed, 1);
    assert_eq!(
        calls.lock().unwrap().deadline,
        Some(now + Duration::from_secs(1))
    );
    calls.lock().unwrap().stop_refuses = true;
    assert!(active.stop(now, false).is_err());
    assert!(!active.complete());
    assert_eq!(calls.lock().unwrap().dropped, 0);
    assert_eq!(calls.lock().unwrap().stopped, 1);
    // The existing Owner/outer Job retains this exact value on uncertainty;
    // this test does not turn a failed stop into a terminal/native claim.
    assert!(active.process.native_token_observation().is_none());
}

#[test]
fn uncertain_cleanup_keeps_process_until_private_peer_exit() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let refused = Pending(calls.clone());
    assert!(retain_on_uncertain_cleanup(refused, Err(ProtocolError)).is_err());
    assert_eq!(calls.lock().unwrap().dropped, 0);

    let complete = Pending(calls.clone());
    assert!(retain_on_uncertain_cleanup(complete, Ok(())).is_ok());
    assert_eq!(calls.lock().unwrap().dropped, 1);
}
