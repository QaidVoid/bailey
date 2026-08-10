//! eBPF observation programs for the bailey audit backend.
//!
//! These tracepoint programs record filesystem opens and outbound TCP connects
//! for the target's process tree and submit them to userspace through a ring
//! buffer. Scoping is by process tree: userspace seeds the target PID into
//! `TRACKED`, and the `fork` program propagates membership to children.
//!
//! The syscall tracepoint field offsets are the stable x86_64 layout for these
//! tracepoints. This is an observation-only design; the programs never deny.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use bailey_common::{AccessRecord, KIND_CONNECT, KIND_READ, KIND_WRITE};

/// PIDs belonging to the audited process tree.
#[map]
static TRACKED: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer carrying access records to userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

const AF_INET: u16 = 2;
const O_ACCMODE: i64 = 0b11;

// Stable x86_64 tracepoint field offsets.
const OPENAT_FILENAME: usize = 24;
const OPENAT_FLAGS: usize = 32;
const CONNECT_SOCKADDR: usize = 24;
const FORK_PARENT_PID: usize = 24;
const FORK_CHILD_PID: usize = 44;

#[tracepoint]
pub fn openat(ctx: TracePointContext) -> u32 {
    let _ = try_openat(&ctx);
    0
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = current_pid();
    if !is_tracked(pid) {
        return Ok(());
    }

    let filename: *const u8 = unsafe { ctx.read_at(OPENAT_FILENAME)? };
    let flags: i64 = unsafe { ctx.read_at(OPENAT_FLAGS)? };
    let kind = if flags & O_ACCMODE != 0 {
        KIND_WRITE
    } else {
        KIND_READ
    };

    let mut entry = match EVENTS.reserve::<AccessRecord>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).kind = kind;
        (*record).pid = pid;
        (*record).addr = 0;
        (*record).port = 0;
        (*record).path_len = 0;
        match bpf_probe_read_user_str_bytes(filename, &mut (*record).path) {
            Ok(read) => (*record).path_len = read.len() as u16,
            Err(_) => {
                entry.discard(0);
                return Ok(());
            }
        }
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn connect(ctx: TracePointContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = current_pid();
    if !is_tracked(pid) {
        return Ok(());
    }

    let sockaddr: usize = unsafe { ctx.read_at::<*const u8>(CONNECT_SOCKADDR)? } as usize;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr as *const u16)? };
    if family != AF_INET {
        return Ok(());
    }
    let port: u16 = unsafe { bpf_probe_read_user((sockaddr + 2) as *const u16)? };
    let addr: u32 = unsafe { bpf_probe_read_user((sockaddr + 4) as *const u32)? };

    let mut entry = match EVENTS.reserve::<AccessRecord>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).kind = KIND_CONNECT;
        (*record).pid = pid;
        (*record).addr = addr;
        (*record).port = port;
        (*record).path_len = 0;
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn fork(ctx: TracePointContext) -> u32 {
    let _ = try_fork(&ctx);
    0
}

fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent = unsafe { ctx.read_at::<i32>(FORK_PARENT_PID)? } as u32;
    if !is_tracked(parent) {
        return Ok(());
    }
    let child = unsafe { ctx.read_at::<i32>(FORK_CHILD_PID)? } as u32;
    let _ = TRACKED.insert(&child, &1, 0);
    Ok(())
}

fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

fn is_tracked(pid: u32) -> bool {
    unsafe { TRACKED.get(&pid).is_some() }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
