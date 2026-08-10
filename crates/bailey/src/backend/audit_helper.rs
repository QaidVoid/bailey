//! Client for the privileged audit helper.
//!
//! The main tool stays unprivileged: it runs the target itself and drives the
//! `bailey-bpf-helper` process, which is the only component that needs
//! `CAP_BPF` and `CAP_PERFMON`. The helper streams fixed-size access records
//! back over a pipe, which this module parses into [`AccessEvent`]s.
//!
//! The helper binary is located via the `BAILEY_BPF_HELPER` environment
//! variable, then next to the running executable, then on `PATH`.

use std::io::{Read, Write};
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

use bailey_common::{AccessRecord, KIND_BIND, KIND_CONNECT, KIND_EXECUTE, KIND_READ, KIND_WRITE};

use crate::backend::{BackendError, Target};
use crate::event::{AccessEvent, AccessKind, Resource};

/// Maximum number of events retained, to bound memory for chatty targets.
const MAX_EVENTS: usize = 200_000;

/// Name of the helper binary.
const HELPER_BIN: &str = "bailey-bpf-helper";

/// Run `target` under observation via the privileged helper and return its exit
/// code and the recorded access trace.
pub fn run(target: &Target) -> Result<(i32, Vec<AccessEvent>), BackendError> {
    let helper_path = locate_helper()?;

    let mut helper = Command::new(&helper_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| {
            BackendError::Unsupported(format!(
                "could not start audit helper `{}`: {err}",
                helper_path.display()
            ))
        })?;

    let mut helper_stdin = helper.stdin.take().expect("piped stdin");
    let mut helper_stdout = helper.stdout.take().expect("piped stdout");

    // Wait for the helper to report that the programs are attached. A failure
    // here is almost always missing privilege.
    let mut ready = [0u8; 1];
    if helper_stdout.read_exact(&mut ready).is_err() {
        let _ = helper.wait();
        return Err(BackendError::Unsupported(
            "audit helper did not start; it needs CAP_BPF and CAP_PERFMON \
             (run it under sudo, or grant the helper the capabilities with setcap)"
                .into(),
        ));
    }

    // Run the target unprivileged, then tell the helper which PID to watch.
    let mut command = Command::new(&target.program);
    command.args(&target.args);
    if let Some(cwd) = &target.cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().map_err(BackendError::Io)?;
    helper_stdin
        .write_all(&child.id().to_le_bytes())
        .map_err(BackendError::Io)?;
    helper_stdin.flush().ok();

    let reader = thread::spawn(move || read_events(&mut helper_stdout));

    let status = child.wait().map_err(BackendError::Io)?;

    // Closing the helper's stdin is the stop signal; it does a final drain and
    // exits, which ends the reader thread at EOF.
    drop(helper_stdin);
    let events = reader.join().unwrap_or_default();
    let _ = helper.wait();

    Ok((status.code().unwrap_or(-1), events))
}

fn read_events(stream: &mut impl Read) -> Vec<AccessEvent> {
    let mut events = Vec::new();
    let mut buf = vec![0u8; size_of::<AccessRecord>()];
    while stream.read_exact(&mut buf).is_ok() {
        if events.len() >= MAX_EVENTS {
            continue;
        }
        let record: &AccessRecord = bytemuck::from_bytes(&buf);
        events.push(to_event(record));
    }
    events
}

fn locate_helper() -> Result<PathBuf, BackendError> {
    if let Some(path) = std::env::var_os("BAILEY_BPF_HELPER") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(HELPER_BIN);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Fall back to PATH resolution by name.
    Ok(PathBuf::from(HELPER_BIN))
}

fn to_event(record: &AccessRecord) -> AccessEvent {
    let kind = match record.kind {
        KIND_READ => AccessKind::Read,
        KIND_WRITE => AccessKind::Write,
        KIND_EXECUTE => AccessKind::Execute,
        KIND_CONNECT => AccessKind::Connect,
        KIND_BIND => AccessKind::Bind,
        _ => AccessKind::Read,
    };

    let resource = match kind {
        AccessKind::Connect | AccessKind::Bind => {
            let octets = record.addr.to_le_bytes();
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            Resource::Net {
                host: Some(ip.to_string()),
                port: u16::from_be(record.port),
            }
        }
        _ => {
            let len = record.path_len as usize;
            let text = String::from_utf8_lossy(&record.path[..len.min(record.path.len())]);
            Resource::Path(PathBuf::from(text.into_owned()))
        }
    };

    AccessEvent {
        kind,
        resource,
        pid: record.pid,
        timestamp_ns: 0,
    }
}
