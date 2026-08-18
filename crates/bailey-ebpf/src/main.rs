//! eBPF observation programs for the bailey audit backend.
//!
//! These are `fentry` programs attached to kernel functions by BTF id. That
//! choice matters twice over: argument layout comes from the running kernel
//! rather than from architecture-specific tracepoint offsets, and attaching
//! needs only the `bpf()` syscall and `/sys/kernel/btf/vmlinux`, not tracefs,
//! which is root-only on a normal system. The privileged helper therefore needs
//! no more than `CAP_BPF` and `CAP_PERFMON`.
//!
//! Hooking `do_filp_open` rather than a syscall entry point means every way of
//! opening a path is covered at once, and the path is read from the kernel's own
//! copy rather than from user memory that could change underneath us.
//!
//! This is an observation-only design; the programs never deny.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{fentry, map},
    maps::{Array, HashMap, RingBuf},
    programs::FEntryContext,
};
use bailey_common::{
    AccessRecord, FAMILY_INET, FAMILY_INET6, KIND_CONNECT, KIND_EXECUTE, KIND_READ, KIND_WRITE,
    NO_CGROUP,
};

/// The audited run's cgroup id, or [`NO_CGROUP`] when the run has none.
///
/// Preferred over the PID set, because cgroup membership is inherited at fork by
/// the kernel: a process is in scope from its first instruction, with no window
/// in which userspace has not yet noticed it exists.
#[map]
static SCOPE: Array<u64> = Array::with_max_entries(1, 0);

/// PIDs belonging to the audited process tree, seeded and maintained by the
/// helper. Used only where the run has no cgroup.
#[map]
static TRACKED: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer carrying access records to userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 22, 0);

/// Count of records that could not be delivered, so a truncated trace can say
/// so rather than looking complete.
#[map]
static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const O_ACCMODE: i32 = 0b11;

/// `struct filename`'s first member is `const char *name`, and
/// `struct open_flags`'s first member is `int open_flag`. Both have been the
/// leading member for the lifetime of these structures, so a read at offset zero
/// needs no CO-RE relocation.
const FILENAME_NAME_OFFSET: usize = 0;
const OPEN_FLAGS_FLAG_OFFSET: usize = 0;

/// `struct sockaddr`: family, then port and address for the inet families.
const SOCKADDR_PORT_OFFSET: usize = 2;
const SOCKADDR_IN_ADDR_OFFSET: usize = 4;
const SOCKADDR_IN6_ADDR_OFFSET: usize = 8;

/// Every path-opening syscall funnels through here.
#[fentry(function = "do_filp_open")]
pub fn open(ctx: FEntryContext) -> u32 {
    let _ = try_open(&ctx);
    0
}

fn try_open(ctx: &FEntryContext) -> Result<(), i64> {
    let pid = current_pid();
    if !in_scope(pid) {
        return Ok(());
    }

    let dirfd: i32 = ctx.arg(0);
    let filename: *const u8 = ctx.arg(1);
    let open_flags: *const u8 = ctx.arg(2);

    let name: *const u8 =
        unsafe { bpf_probe_read_kernel(filename.add(FILENAME_NAME_OFFSET) as *const *const u8)? };
    let flags: i32 =
        unsafe { bpf_probe_read_kernel(open_flags.add(OPEN_FLAGS_FLAG_OFFSET) as *const i32)? };

    let kind = if flags & O_ACCMODE != 0 {
        KIND_WRITE
    } else {
        KIND_READ
    };

    submit(|record| {
        record.kind = kind;
        record.pid = pid;
        record.dirfd = dirfd;
        record.flags = flags as u32;
        unsafe {
            match bpf_probe_read_kernel_str_bytes(name, &mut record.path) {
                Ok(read) => {
                    record.path_len = read.len() as u16;
                    true
                }
                Err(_) => false,
            }
        }
    })
}

/// The kernel opens a program's image here before executing it.
#[fentry(function = "do_open_execat")]
pub fn exec(ctx: FEntryContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn try_exec(ctx: &FEntryContext) -> Result<(), i64> {
    let pid = current_pid();
    if !in_scope(pid) {
        return Ok(());
    }

    let dirfd: i32 = ctx.arg(0);
    let filename: *const u8 = ctx.arg(1);
    let name: *const u8 =
        unsafe { bpf_probe_read_kernel(filename.add(FILENAME_NAME_OFFSET) as *const *const u8)? };

    submit(|record| {
        record.kind = KIND_EXECUTE;
        record.pid = pid;
        record.dirfd = dirfd;
        unsafe {
            match bpf_probe_read_kernel_str_bytes(name, &mut record.path) {
                Ok(read) => {
                    record.path_len = read.len() as u16;
                    true
                }
                Err(_) => false,
            }
        }
    })
}

/// The address here has already been copied into kernel memory, and covers both
/// inet families.
#[fentry(function = "security_socket_connect")]
pub fn connect(ctx: FEntryContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &FEntryContext) -> Result<(), i64> {
    let pid = current_pid();
    if !in_scope(pid) {
        return Ok(());
    }

    let address: *const u8 = ctx.arg(1);
    let family: u16 = unsafe { bpf_probe_read_kernel(address as *const u16)? };
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }

    let port: u16 =
        unsafe { bpf_probe_read_kernel(address.add(SOCKADDR_PORT_OFFSET) as *const u16)? };

    let mut addr = [0u8; 16];
    if family == AF_INET {
        let raw: [u8; 4] = unsafe {
            bpf_probe_read_kernel(address.add(SOCKADDR_IN_ADDR_OFFSET) as *const [u8; 4])?
        };
        addr[..4].copy_from_slice(&raw);
    } else {
        addr = unsafe {
            bpf_probe_read_kernel(address.add(SOCKADDR_IN6_ADDR_OFFSET) as *const [u8; 16])?
        };
    }

    submit(|record| {
        record.kind = KIND_CONNECT;
        record.pid = pid;
        record.family = if family == AF_INET {
            FAMILY_INET
        } else {
            FAMILY_INET6
        };
        record.port = u16::from_be(port);
        record.addr = addr;
        true
    })
}

/// Reserve a record, let `fill` populate it, and submit it.
///
/// A record that cannot be reserved, or that `fill` rejects, increments the
/// dropped counter so userspace can report the trace as incomplete.
fn submit(fill: impl FnOnce(&mut AccessRecord) -> bool) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<AccessRecord>(0) else {
        count_drop();
        return Ok(());
    };

    let record = entry.as_mut_ptr();
    unsafe {
        (*record) = AccessRecord::empty();
        (*record).timestamp_ns = bpf_ktime_get_ns();
        if !fill(&mut *record) {
            entry.discard(0);
            count_drop();
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

fn count_drop() {
    if let Some(slot) = DROPPED.get_ptr_mut(0) {
        unsafe { *slot += 1 };
    }
}

fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Whether the current task belongs to the audited run.
fn in_scope(pid: u32) -> bool {
    match SCOPE.get(0).copied().unwrap_or(NO_CGROUP) {
        NO_CGROUP => unsafe { TRACKED.get(&pid).is_some() },
        cgroup => unsafe { generated::bpf_get_current_cgroup_id() == cgroup },
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
