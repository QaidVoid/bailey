//! Minimal privileged helper for bailey's audit backend.
//!
//! This is the only component that needs `CAP_BPF` and `CAP_PERFMON`. It loads
//! the eBPF observation programs, attaches them by BTF id, and streams access
//! records to its stdout. It never spawns or touches the target: the
//! unprivileged parent runs the target and sends its PID on stdin.
//!
//! Attaching by BTF id rather than through tracefs matters for privilege:
//! tracefs is root-only on a normal system, so a tracefs-based attach would
//! force this binary to carry `CAP_DAC_READ_SEARCH` as well.
//!
//! Protocol, all on the helper's stdin/stdout:
//!
//! 1. The helper loads and attaches, then writes `HELLO` and `PROTOCOL_VERSION`.
//! 2. The parent writes the target PID as 4 little-endian bytes.
//! 3. The helper seeds the PID and writes `ACK`. Only then may the parent let
//!    the target run, so nothing it does is missed.
//! 4. The helper streams `FRAME_RECORD` frames, each followed by an
//!    `AccessRecord`.
//! 5. When the parent closes stdin, the helper drains, writes a
//!    `FRAME_SUMMARY` frame with the count of undeliverable records, and exits.
//!
//! Keeping this surface tiny is the point: the privileged code loads a fixed set
//! of programs and copies bytes, nothing else.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::mem::size_of;
use std::thread;
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::FEntry;
use aya::{Btf, Ebpf, include_bytes_aligned};
use bailey_common::{ACK, AccessRecord, FRAME_RECORD, FRAME_SUMMARY, HELLO, PROTOCOL_VERSION};

/// How often the descendant set is refreshed.
///
/// Membership is discovered by reading `/proc`, so a process that is born and
/// dies between two passes is missed entirely. The interval is short because
/// that window is the difference between seeing what a target's children did and
/// not seeing it at all.
const POLL_INTERVAL: Duration = Duration::from_micros(200);

/// Programs to load, paired with the kernel function each attaches to.
const PROGRAMS: &[(&str, &str)] = &[
    ("open", "do_filp_open"),
    ("exec", "do_open_execat"),
    ("connect", "security_socket_connect"),
];

fn main() {
    if let Err(err) = run() {
        eprintln!("bailey-bpf-helper: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bailey-ebpf"
    )))?;

    let btf = Btf::from_sys_fs()?;
    for (program, function) in PROGRAMS {
        let fentry: &mut FEntry = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow::anyhow!("program `{program}` missing"))?
            .try_into()?;
        fentry.load(function, &btf)?;
        fentry.attach()?;
    }

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?,
    )?;
    let mut tracked: AyaHashMap<MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map("TRACKED")
            .ok_or_else(|| anyhow::anyhow!("TRACKED map missing"))?,
    )?;
    let dropped: Array<MapData, u64> = Array::try_from(
        ebpf.take_map("DROPPED")
            .ok_or_else(|| anyhow::anyhow!("DROPPED map missing"))?,
    )?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&[HELLO, PROTOCOL_VERSION])?;
    stdout.flush()?;

    // Blocking read: the parent is holding the target before exec until the
    // acknowledgement below, so there is nothing to race with yet.
    let mut pid_bytes = [0u8; 4];
    read_exact_fd(libc::STDIN_FILENO, &mut pid_bytes)?;
    let target = u32::from_le_bytes(pid_bytes);

    tracked.insert(target, 1, 0)?;
    let mut known = BTreeSet::from([target]);

    stdout.write_all(&[ACK])?;
    stdout.flush()?;

    set_nonblocking(libc::STDIN_FILENO);

    loop {
        follow_descendants(&mut tracked, &mut known);
        drain(&mut ring, &mut stdout)?;
        if stdin_closed() {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    follow_descendants(&mut tracked, &mut known);
    drain(&mut ring, &mut stdout)?;

    let lost = dropped.get(&0, 0).unwrap_or(0);
    stdout.write_all(&[FRAME_SUMMARY])?;
    stdout.write_all(&lost.to_le_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// Add processes the tracked set has spawned.
///
/// Membership is by process tree, read from `/proc`, because scoping by cgroup
/// needs a delegated cgroup that is not always available. The kernel side keeps
/// only a set of PIDs, so this is the piece that keeps it current.
fn follow_descendants(tracked: &mut AyaHashMap<MapData, u32, u8>, known: &mut BTreeSet<u32>) {
    let mut frontier: Vec<u32> = known.iter().copied().collect();
    while let Some(pid) = frontier.pop() {
        for child in children_of(pid) {
            if known.insert(child) {
                let _ = tracked.insert(child, 1, 0);
                frontier.push(child);
            }
        }
    }
}

fn children_of(pid: u32) -> Vec<u32> {
    let mut children = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return children;
    };
    for task in tasks.flatten() {
        let path = task.path().join("children");
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        children.extend(
            content
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok()),
        );
    }
    children
}

fn drain(ring: &mut RingBuf<MapData>, stdout: &mut impl Write) -> io::Result<()> {
    let record_size = size_of::<AccessRecord>();
    while let Some(item) = ring.next() {
        let bytes: &[u8] = &item;
        if bytes.len() >= record_size {
            stdout.write_all(&[FRAME_RECORD])?;
            stdout.write_all(&bytes[..record_size])?;
        }
    }
    stdout.flush()
}

fn read_exact_fd(fd: libc::c_int, buf: &mut [u8]) -> io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[read..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - read,
            )
        };
        match n {
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            -1 => return Err(io::Error::last_os_error()),
            n => read += n as usize,
        }
    }
    Ok(())
}

fn set_nonblocking(fd: libc::c_int) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn stdin_closed() -> bool {
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::read(
            libc::STDIN_FILENO,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    // 0 is EOF; -1 with EAGAIN means still open with no data.
    n == 0
}
