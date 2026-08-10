//! eBPF-backed implementation of the audit backend.
//!
//! Loads the observation programs, attaches them to the openat, connect, and
//! fork tracepoints, runs the target permissively while recording its process
//! tree's access, and returns the collected trace. Compiled only with the
//! `ebpf` feature. Loading the programs requires `CAP_BPF` and `CAP_PERFMON`
//! (run under `sudo`, or grant the binary the capabilities with `setcap`).

use std::mem::size_of;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use bailey_common::{AccessRecord, KIND_BIND, KIND_CONNECT, KIND_EXECUTE, KIND_READ, KIND_WRITE};

use crate::backend::{BackendError, Target};
use crate::event::{AccessEvent, AccessKind, Resource};

/// Maximum number of events retained, to bound memory for chatty targets.
const MAX_EVENTS: usize = 200_000;

/// Run `target` permissively under eBPF observation and return its exit code
/// and the recorded access trace.
pub fn run(target: &Target) -> Result<(i32, Vec<AccessEvent>), BackendError> {
    let mut ebpf = load()?;
    attach(&mut ebpf)?;

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| BackendError::Unsupported("EVENTS map missing".into()))?,
    )
    .map_err(|err| BackendError::Unsupported(format!("ring buffer: {err}")))?;

    let mut command = Command::new(&target.program);
    command.args(&target.args);
    if let Some(cwd) = &target.cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().map_err(BackendError::Io)?;

    track_pid(&mut ebpf, child.id())?;

    let mut trace = Vec::new();
    let mut truncated = false;
    let code = loop {
        drain(&mut ring, &mut trace, &mut truncated);
        if let Some(status) = child.try_wait().map_err(BackendError::Io)? {
            break status.code().unwrap_or(-1);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drain(&mut ring, &mut trace, &mut truncated);

    if truncated {
        eprintln!("bailey: warning: audit trace truncated at {MAX_EVENTS} events");
    }
    Ok((code, trace))
}

fn load() -> Result<Ebpf, BackendError> {
    Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bailey-ebpf"
    )))
    .map_err(|err| {
        BackendError::Unsupported(format!(
            "loading eBPF programs failed ({err}); audit needs CAP_BPF and CAP_PERFMON \
             (run with sudo or grant the binary the capabilities with setcap)"
        ))
    })
}

fn attach(ebpf: &mut Ebpf) -> Result<(), BackendError> {
    for (program, category, name) in [
        ("openat", "syscalls", "sys_enter_openat"),
        ("connect", "syscalls", "sys_enter_connect"),
        ("fork", "sched", "sched_process_fork"),
    ] {
        let tp: &mut TracePoint = ebpf
            .program_mut(program)
            .ok_or_else(|| BackendError::Unsupported(format!("program `{program}` missing")))?
            .try_into()
            .map_err(|err| BackendError::Unsupported(format!("program `{program}`: {err}")))?;
        tp.load()
            .map_err(|err| BackendError::Unsupported(format!("load `{program}`: {err}")))?;
        tp.attach(category, name)
            .map_err(|err| BackendError::Unsupported(format!("attach `{program}`: {err}")))?;
    }
    Ok(())
}

fn track_pid(ebpf: &mut Ebpf, pid: u32) -> Result<(), BackendError> {
    let mut tracked: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.map_mut("TRACKED")
            .ok_or_else(|| BackendError::Unsupported("TRACKED map missing".into()))?,
    )
    .map_err(|err| BackendError::Unsupported(format!("tracked map: {err}")))?;
    tracked
        .insert(pid, 1, 0)
        .map_err(|err| BackendError::Unsupported(format!("seed pid: {err}")))?;
    Ok(())
}

fn drain(ring: &mut RingBuf<MapData>, trace: &mut Vec<AccessEvent>, truncated: &mut bool) {
    while let Some(item) = ring.next() {
        if trace.len() >= MAX_EVENTS {
            *truncated = true;
            continue;
        }
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<AccessRecord>() {
            continue;
        }
        let record: &AccessRecord = bytemuck::from_bytes(&bytes[..size_of::<AccessRecord>()]);
        trace.push(to_event(record));
    }
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
            let text = String::from_utf8_lossy(&record.path[..len]);
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
