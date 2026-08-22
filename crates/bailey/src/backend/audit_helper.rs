//! Client for the privileged audit helper.
//!
//! The main tool stays unprivileged: it runs the target itself, under the
//! enforcement backend, and drives the `bailey-bpf-helper` process, which is the
//! only component that needs `CAP_BPF` and `CAP_PERFMON`.
//!
//! The order of the handshake is what makes the trace complete. The target is
//! spawned stopped, its PID is handed to the helper, and only once the helper
//! acknowledges that observation is in place is the target allowed to run. A
//! target released before then would do its most interesting work, loading its
//! libraries, unobserved.
//!
//! The helper binary is located via the `BAILEY_BPF_HELPER` environment
//! variable, then next to the running executable, then on `PATH`.

use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use bailey_common::{
    ACK, AccessRecord, FAMILY_INET, FAMILY_INET6, FRAME_RECORD, FRAME_SUMMARY, HELLO, KIND_BIND,
    KIND_CONNECT, KIND_EXECUTE, KIND_READ, KIND_WRITE, NO_CGROUP, PROTOCOL_VERSION,
};

use crate::backend::enforce::Confined;
use crate::backend::{BackendError, Target};
use crate::event::{AccessEvent, AccessKind, Resolution, Resource, Trace};

/// Maximum number of events retained, to bound memory for chatty targets.
const MAX_EVENTS: usize = 200_000;

/// How long to wait for the target to stop before exec, and for the helper to
/// acknowledge the scope.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Name of the helper binary.
const HELPER_BIN: &str = "bailey-bpf-helper";

/// A running helper, ready to be told which process to observe.
pub struct Recorder {
    process: Child,
    stdin: std::process::ChildStdin,
    stdout: ChildStdout,
}

impl Recorder {
    /// Start the helper and wait for it to report its programs attached.
    pub fn start() -> Result<Self, BackendError> {
        let helper_path = locate_helper()?;

        let mut process = Command::new(&helper_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| {
                BackendError::Unsupported(format!(
                    "could not start audit helper `{}`: {err}",
                    helper_path.display()
                ))
            })?;

        let stdin = process.stdin.take().expect("piped stdin");
        let mut stdout = process.stdout.take().expect("piped stdout");

        let mut hello = [0u8; 2];
        if stdout.read_exact(&mut hello).is_err() {
            let _ = process.wait();
            return Err(BackendError::Unsupported(
                "audit helper did not start; it needs CAP_BPF and CAP_PERFMON \
                 (grant them with `setcap cap_bpf,cap_perfmon+ep`, or run under a \
                 privileged shell). Its own error is above."
                    .into(),
            ));
        }
        if hello[0] != HELLO {
            return Err(BackendError::Unsupported(
                "audit helper sent an unrecognised greeting".into(),
            ));
        }
        if hello[1] != PROTOCOL_VERSION {
            return Err(BackendError::Unsupported(format!(
                "audit helper speaks protocol version {}, this build speaks {}; \
                 rebuild the helper",
                hello[1], PROTOCOL_VERSION
            )));
        }

        Ok(Self {
            process,
            stdin,
            stdout,
        })
    }

    /// Tell the helper what to observe, and wait for it to confirm.
    ///
    /// A cgroup id scopes observation exactly, since membership is inherited at
    /// fork; without one the helper follows the process tree, which cannot see a
    /// process that is born and reaped between two passes.
    pub fn observe(&mut self, pid: u32, cgroup: u64) -> Result<(), BackendError> {
        let mut scope = [0u8; 12];
        scope[..4].copy_from_slice(&pid.to_le_bytes());
        scope[4..].copy_from_slice(&cgroup.to_le_bytes());
        self.stdin.write_all(&scope).map_err(BackendError::Io)?;
        self.stdin.flush().map_err(BackendError::Io)?;

        let mut ack = [0u8; 1];
        self.stdout.read_exact(&mut ack).map_err(|_| {
            BackendError::Unsupported("audit helper did not confirm the observation scope".into())
        })?;
        if ack[0] != ACK {
            return Err(BackendError::Unsupported(
                "audit helper sent an unrecognised acknowledgement".into(),
            ));
        }
        Ok(())
    }

    /// Stop recording and collect the trace.
    pub fn finish(mut self) -> Trace {
        // Closing stdin is the stop signal; the helper drains, writes its
        // summary, and exits.
        drop(self.stdin);
        let trace = read_frames(&mut self.stdout);
        let _ = self.process.wait();
        trace
    }
}

/// Run `confined` under observation and return its exit code with the trace.
///
/// The target arrives stopped before exec. It is released only after the helper
/// confirms it is watching.
pub fn record(recorder: &mut Recorder, confined: Confined) -> Result<i32, BackendError> {
    let pid = confined.pid();
    let cgroup = confined.cgroup_id().unwrap_or(NO_CGROUP);
    if cgroup == NO_CGROUP {
        eprintln!(
            "bailey: warning: no cgroup for this run, so observation follows the \
             process tree; a process that is born and reaped between passes can \
             be missed. Run `bailey doctor` for why."
        );
    }
    wait_for_stop(pid)?;
    recorder.observe(pid, cgroup)?;
    resume(pid)?;
    confined.wait()
}

/// Wait for the target to reach its pre-exec stop.
fn wait_for_stop(pid: u32) -> Result<(), BackendError> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let mut status: libc::c_int = 0;
        let result = unsafe {
            libc::waitpid(
                pid as libc::pid_t,
                &mut status,
                libc::WUNTRACED | libc::WNOHANG,
            )
        };
        if result > 0 && libc::WIFSTOPPED(status) {
            return Ok(());
        }
        if result > 0 {
            return Err(BackendError::Unsupported(
                "the target exited before it could be observed".into(),
            ));
        }
        if Instant::now() > deadline {
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            return Err(BackendError::Unsupported(
                "the target did not stop for observation within the timeout".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Release the target, and stop tracing it.
///
/// The target was stopped by the exec trap of its own `PTRACE_TRACEME`, so
/// detaching is what lets it run; it then executes with no tracer attached.
fn resume(pid: u32) -> Result<(), BackendError> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result != 0 {
        return Err(BackendError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Read the helper's framed stream into a trace.
fn read_frames(stream: &mut impl Read) -> Trace {
    let mut events = Vec::new();
    let mut dropped = 0u64;
    let mut record_buf = vec![0u8; size_of::<AccessRecord>()];
    let mut tag = [0u8; 1];

    while stream.read_exact(&mut tag).is_ok() {
        match tag[0] {
            FRAME_RECORD => {
                if stream.read_exact(&mut record_buf).is_err() {
                    break;
                }
                if events.len() >= MAX_EVENTS {
                    dropped += 1;
                    continue;
                }
                let record: &AccessRecord = bytemuck::from_bytes(&record_buf);
                events.push(to_event(record));
            }
            FRAME_SUMMARY => {
                let mut lost = [0u8; 8];
                if stream.read_exact(&mut lost).is_err() {
                    break;
                }
                dropped += u64::from_le_bytes(lost);
            }
            _ => break,
        }
    }

    Trace::new(events, dropped)
}

fn locate_helper() -> Result<PathBuf, BackendError> {
    crate::backend::probe::locate_helper().ok_or_else(|| {
        BackendError::Unsupported(format!(
            "no `{HELPER_BIN}` found. Looked at $BAILEY_BPF_HELPER, beside this \
             executable, and on PATH. Build it with `cargo build --release -p \
             bailey-bpf-helper`, then grant it capabilities with `setcap \
             cap_bpf,cap_perfmon+ep`."
        ))
    })
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

    let (resource, resolution) = match kind {
        AccessKind::Connect | AccessKind::Bind => {
            let host = match record.family {
                FAMILY_INET => {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&record.addr[..4]);
                    Some(Ipv4Addr::from(octets).to_string())
                }
                FAMILY_INET6 => Some(Ipv6Addr::from(record.addr).to_string()),
                _ => None,
            };
            (
                Resource::Net {
                    host,
                    port: record.port,
                },
                Resolution::NotApplicable,
            )
        }
        _ => {
            let len = (record.path_len as usize).min(record.path.len());
            let raw = String::from_utf8_lossy(&record.path[..len]);
            let raw = raw.trim_end_matches('\0');
            let path = PathBuf::from(raw);
            if path.is_absolute() {
                (Resource::Path(path), Resolution::Absolute)
            } else {
                match resolve_relative(record.pid, record.dirfd, &path) {
                    Some(absolute) => (Resource::Path(absolute), Resolution::Userspace),
                    None => (Resource::Path(path), Resolution::Unresolved),
                }
            }
        }
    };

    AccessEvent {
        kind,
        resource,
        pid: record.pid,
        timestamp_ns: record.timestamp_ns,
        resolution,
    }
}

/// Resolve a relative path against the accessing process's directory.
///
/// This is racy by nature: the process may have moved on, or exited, before the
/// link can be read. An event that cannot be resolved says so rather than being
/// compared against policy paths as though it were absolute.
fn resolve_relative(pid: u32, dirfd: i32, path: &Path) -> Option<PathBuf> {
    let base = if dirfd == bailey_common::AT_FDCWD {
        PathBuf::from(format!("/proc/{pid}/cwd"))
    } else {
        PathBuf::from(format!("/proc/{pid}/fd/{dirfd}"))
    };
    let base = std::fs::read_link(base).ok()?;
    Some(base.join(path))
}

/// Run `target` under observation via the privileged helper, without
/// confinement. Kept for callers that explicitly opt out of the audit envelope.
pub fn run_unconfined(target: &Target) -> Result<(i32, Trace), BackendError> {
    let mut recorder = Recorder::start()?;

    let mut command = Command::new(&target.program);
    command.args(&target.args);
    if let Some(cwd) = &target.cwd {
        command.current_dir(cwd);
    }
    // Safety: single-threaded at this point, and the closure only raises a
    // signal on itself.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(BackendError::Io)?;
    let pid = child.id();
    wait_for_stop(pid)?;
    // An unconfined run has no cgroup of its own to scope to.
    recorder.observe(pid, NO_CGROUP)?;
    resume(pid)?;
    let status = child.wait().map_err(BackendError::Io)?;
    let trace = recorder.finish();
    Ok((status.code().unwrap_or(-1), trace))
}
