//! Minimal privileged helper for bailey's audit backend.
//!
//! This is the only component that needs `CAP_BPF` and `CAP_PERFMON`. It loads
//! the eBPF observation programs, attaches them, and streams fixed-size access
//! records to its stdout. It never spawns or touches the target: the
//! unprivileged parent runs the target and sends its PID on stdin.
//!
//! Protocol, all on the helper's stdin/stdout:
//!
//! 1. On startup the helper loads and attaches, then writes one `0x01` ready
//!    byte to stdout.
//! 2. The parent writes the target PID as 4 little-endian bytes to stdin.
//! 3. The helper seeds the PID and streams `AccessRecord`-sized frames to stdout.
//! 4. When the parent closes stdin (EOF), the helper does a final drain and
//!    exits.
//!
//! Keeping this surface tiny is the point: the privileged code loads a fixed set
//! of programs and copies bytes, nothing else.

use std::io::{self, Write};
use std::mem::size_of;
use std::thread;
use std::time::Duration;

use aya::maps::{HashMap as AyaHashMap, RingBuf};
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use bailey_common::AccessRecord;

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

    for (program, category, name) in [
        ("openat", "syscalls", "sys_enter_openat"),
        ("connect", "syscalls", "sys_enter_connect"),
        ("fork", "sched", "sched_process_fork"),
    ] {
        let tp: &mut TracePoint = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow::anyhow!("program `{program}` missing"))?
            .try_into()?;
        tp.load()?;
        tp.attach(category, name)?;
    }

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?,
    )?;

    // Signal that the programs are attached before the parent starts the target.
    let mut stdout = io::stdout().lock();
    stdout.write_all(&[0x01])?;
    stdout.flush()?;

    // Read the target PID (4 little-endian bytes) with a blocking raw read.
    let mut pid_bytes = [0u8; 4];
    read_exact_fd(libc::STDIN_FILENO, &mut pid_bytes)?;
    let pid = u32::from_le_bytes(pid_bytes);

    {
        let mut tracked: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            ebpf.map_mut("TRACKED")
                .ok_or_else(|| anyhow::anyhow!("TRACKED map missing"))?,
        )?;
        tracked.insert(pid, 1, 0)?;
    }

    // Watch stdin for EOF (the parent closing it is the stop signal) without
    // blocking the streaming loop.
    set_nonblocking(libc::STDIN_FILENO);

    let record_size = size_of::<AccessRecord>();
    loop {
        drain(&mut ring, &mut stdout, record_size)?;
        if stdin_closed() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    drain(&mut ring, &mut stdout, record_size)?;
    stdout.flush()?;
    Ok(())
}

fn drain(
    ring: &mut RingBuf<aya::maps::MapData>,
    stdout: &mut impl Write,
    record_size: usize,
) -> io::Result<()> {
    while let Some(item) = ring.next() {
        let bytes: &[u8] = &item;
        if bytes.len() >= record_size {
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
