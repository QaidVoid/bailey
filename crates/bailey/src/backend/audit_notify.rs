//! The seccomp user-notification fallback observer.
//!
//! Where the privileged helper cannot run, the audit still records: a small
//! classic-BPF filter returns `SECCOMP_RET_USER_NOTIF` for the syscalls the
//! eBPF programs hook (opens, executions and connects), and a supervisor
//! thread in bailey answers each notification. The filter stacks after the
//! denylist, so a syscall the denylist refuses is never notified, and
//! observation stays inside the same confinement an eBPF audit has.
//!
//! The child arms the filter last in `pre_exec` and hands the listener over
//! through `SCM_RIGHTS`. The supervisor reads each notification's path or
//! address out of `/proc/<pid>/mem` on a bounded-time reader thread, resolves
//! relative paths against the notifying process, replies
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and records the same
//! [`crate::event::AccessEvent`]s the eBPF observer records. It never
//! enforces: the reply is the same whatever was read, so no access decision
//! depends on it.
//!
//! Costs and blind spots are the caller's to report: an observed syscall pays
//! a round trip to bailey, kernel-internal opens (ELF and script
//! interpreters) are never seen, and a racing writer can skew the trace.

use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use libc::pollfd;

use super::enforce::NATIVE_AUDIT_ARCH;
use super::fdpass;
use crate::backend::audit_helper::MAX_EVENTS;
use crate::event::{AccessEvent, AccessKind, Resolution, Resource};

/// How long a memory read may take before it is abandoned.
///
/// Reading target memory faults pages in, and a page on a FUSE or network
/// filesystem can block for seconds. The supervisor waits this long on the
/// reader thread, then counts the access as dropped, continues the syscall,
/// and replaces the reader.
pub(crate) const MEMORY_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Abandonments over a whole run after which memory reads stop entirely.
///
/// A target that stalls reads one after another could otherwise make bailey
/// replace readers forever. Past this many, every further notification is
/// dropped unread and continued at once, and the trace carries the reason.
pub(crate) const MAX_ABANDONED_READERS: u32 = 4;

/// Test-only hook: when this variable is set, every memory read fails.
///
/// The ptrace policies that make reads fail need a hardened kernel setting to
/// reproduce, so integration tests force the failure through this hook to
/// exercise the fatal path. Nothing outside tests sets it.
const TEST_FAIL_MEMORY_READ: &str = "BAILEY_TEST_FAIL_MEMORY_READ";

/// Test-only hook: when this flag is set, an id answers valid the first
/// time it is checked and invalid afterwards.
///
/// A target that exits while its memory is being read cannot be timed in a
/// test, so the hook expires the id between the pre-read check and the
/// post-read one. It is global to the process, so the test that sets it
/// holds `SUPERVISE_LOCK` across the flag and no other supervisor consults
/// it mid-flight.
static TEST_EXPIRE_IDS: AtomicBool = AtomicBool::new(false);

/// Longest path the supervisor reads out of target memory.
const PATH_MAX: usize = 4096;

/// Directory descriptor meaning "resolve against the caller's working
/// directory".
const AT_FDCWD: i64 = -100;
/// `execveat` flag meaning the path argument is empty and `dirfd` names the
/// file itself.
const AT_EMPTY_PATH: u64 = 0x1000;
/// `openat2` restriction that resolves absolute paths inside `dirfd`.
const RESOLVE_IN_ROOT: u64 = 0x10;
/// Every `openat2` resolve bit this build knows. A bit outside it means the
/// kernel will interpret the path in a way this build cannot describe.
const KNOWN_RESOLVE_BITS: u64 = 0x3f;
/// Access-mode bits of an open flags word.
const O_ACCMODE: u64 = 3;
/// The read-only access mode.
const O_RDONLY: u64 = 0;

// Classic BPF opcodes and seccomp offsets, which libc does not name.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;

/// Syscalls the fallback observer records, by the numbers this build's
/// architecture uses. `open` and `creat` exist only on x86_64.
#[cfg(target_arch = "x86_64")]
const OBSERVED: [i64; 7] = [
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_creat,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_connect,
];
#[cfg(target_arch = "aarch64")]
const OBSERVED: [i64; 5] = [
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_connect,
];

/// What one notification contributed to the trace.
enum Step {
    /// An event was built and recorded.
    Recorded(AccessEvent),
    /// The access counted toward `dropped`.
    Dropped,
    /// Nothing to record: a family or shape the observer does not describe.
    Skipped,
    /// The first notification's memory read failed, and the run ends.
    Fatal(String),
}

/// A memory read the supervisor asks a reader thread to perform.
struct ReadJob {
    pid: u32,
    addr: u64,
    len: usize,
    reply: mpsc::Sender<io::Result<Vec<u8>>>,
}

/// One memory reader thread and the reads it has left in it.
///
/// A read that blocks past [`MEMORY_READ_TIMEOUT`] is abandoned: the reader
/// keeps running until its read returns, owns everything it touches, and
/// exits when its reply finds no receiver. The supervisor starts a fresh
/// reader and never waits for the old one.
struct Reads {
    reader: mpsc::Sender<ReadJob>,
    stalled: u32,
    blinded: bool,
}

impl Reads {
    fn start() -> Self {
        let (reader, jobs) = mpsc::channel::<ReadJob>();
        std::thread::Builder::new()
            .name("audit-memread".into())
            .spawn(move || {
                for job in jobs {
                    let result = read_memory_now(job.pid, job.addr, job.len);
                    let _ = job.reply.send(result);
                }
            })
            .expect("spawning the audit memory reader thread");
        Self {
            reader,
            stalled: 0,
            blinded: false,
        }
    }

    /// Read `len` bytes of target memory, bounded in time.
    ///
    /// In blind mode every read fails at once, because no reader runs any
    /// more.
    fn read(&mut self, pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        if self.blinded {
            return Err(io::Error::from_raw_os_error(libc::ECANCELED));
        }
        let (reply, waiting) = mpsc::channel();
        if self
            .reader
            .send(ReadJob {
                pid,
                addr,
                len,
                reply,
            })
            .is_err()
        {
            return Err(io::Error::other("the memory reader thread is gone"));
        }
        match waiting.recv_timeout(MEMORY_READ_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.stalled += 1;
                // At the abandonment bound the run goes blind and no read
                // is ever sent again, so no replacement reader starts for
                // the read that crossed the line.
                if self.stalled >= MAX_ABANDONED_READERS {
                    self.blinded = true;
                } else {
                    self.reader = Reads::start().reader;
                }
                Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("the memory reader thread is gone"))
            }
        }
    }
}

/// Read target memory straight through `/proc/<pid>/mem`.
///
/// This can block on the mapping's backing filesystem, which is why the
/// supervisor only calls it from a reader thread. A cached descriptor could
/// outlive its task and read a dead process's memory under a reused PID, so
/// the file is opened for every read.
pub(crate) fn read_memory_now(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    if std::env::var_os(TEST_FAIL_MEMORY_READ).is_some() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = vec![0u8; len];
    let read = unsafe {
        libc::pread(
            mem.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            len,
            addr as libc::off_t,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(read as usize);
    Ok(buf)
}

/// Build the notification filter: the architecture check, `USER_NOTIF` for
/// the observed syscalls, `ALLOW` for everything else.
///
/// A foreign architecture returns `ALLOW` because the denylist already
/// refuses it with an errno, which outranks `ALLOW`; the same precedence is
/// why no x32 check is needed on x86_64. This runs in the forked child, so it
/// allocates only before the child is expected to be allocation-free.
pub(crate) fn filter() -> Vec<libc::sock_filter> {
    let mut program = vec![
        stmt(BPF_LD_W_ABS, ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, NATIVE_AUDIT_ARCH, 1, 0),
        stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_LD_W_ABS, NR_OFFSET),
    ];
    for nr in OBSERVED {
        program.push(jump(BPF_JMP_JEQ_K, nr as u32, 0, 1));
        program.push(stmt(BPF_RET_K, libc::SECCOMP_RET_USER_NOTIF));
    }
    program.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    program
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Install `filter` on this task with `SECCOMP_FILTER_FLAG_NEW_LISTENER`,
/// returning the listener descriptor.
pub(crate) fn install(filter: &[libc::sock_filter]) -> io::Result<RawFd> {
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &program as *const libc::sock_fprog,
        )
    };
    // The errno travels with the error: the availability probe classifies
    // EBUSY as "already observed", and a caller that wants to name the
    // cause maps it where the user is looking.
    if listener < 0 {
        return Err(io::Error::last_os_error());
    }
    let listener = listener as RawFd;
    // The listener must not survive into the target.
    unsafe { libc::fcntl(listener, libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(listener)
}

/// Arm the filter in the forked child and hand the listener to the
/// supervisor over `handover`.
///
/// Called last in `pre_exec`, so the only notified syscall left in the child
/// is the exec itself.
pub(crate) fn arm(handover: RawFd) -> io::Result<()> {
    let program = filter();
    let listener = install(&program)?;
    let sent = fdpass::send_fds(handover, &[listener]);
    unsafe { libc::close(listener) };
    sent
}

/// The struct sizes this kernel answers notifications with, asked of the
/// `seccomp` syscall itself, whose `SECCOMP_GET_NOTIF_SIZES` operation is
/// what owns them.
pub(crate) fn notif_sizes() -> io::Result<(usize, usize)> {
    let mut sizes = libc::seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0u32,
            &mut sizes as *mut libc::seccomp_notif_sizes,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let response = (sizes.seccomp_notif_resp as usize).max(size_of::<libc::seccomp_notif_resp>());
    Ok((sizes.seccomp_notif as usize, response))
}

/// Read one notification off the listener. `ENOENT` from an interrupted
/// syscall comes back as that error.
pub(crate) fn recv_notification(listener: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, buf.as_mut_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Whether the notification id still belongs to a live syscall.
fn id_valid(listener: RawFd, id: u64) -> bool {
    if TEST_EXPIRE_IDS.load(Ordering::SeqCst) {
        static CHECKS: AtomicUsize = AtomicUsize::new(0);
        return CHECKS.fetch_add(1, Ordering::SeqCst) == 0;
    }
    let rc = unsafe {
        libc::ioctl(
            listener,
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            &id as *const u64 as *mut libc::c_void,
        )
    };
    rc == 0
}

/// Reply `CONTINUE`, handing the syscall back to the kernel unchanged.
///
/// `ENOENT` means the syscall was interrupted and will be notified again on
/// restart; the caller ignores it.
pub(crate) fn reply_continue(listener: RawFd, id: u64, buf: &mut [u8]) -> io::Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    let bytes = size_of::<libc::seccomp_notif_resp>();
    if buf.len() < bytes {
        return Err(io::Error::other(
            "the response buffer is smaller than the kernel asked for",
        ));
    }
    unsafe {
        std::ptr::copy_nonoverlapping((&raw const resp).cast::<u8>(), buf.as_mut_ptr(), bytes);
    }
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, buf.as_mut_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// What the supervisor collected over one run.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// The recorded accesses, in notification order.
    pub events: Vec<AccessEvent>,
    /// The accesses that could not be recorded, for any reason.
    pub dropped: u64,
    /// Why reads stopped entirely, when they did.
    pub loss: Option<String>,
    /// Why the run could not be recorded at all, when the first read failed.
    pub failure: Option<String>,
}

/// A running supervisor and its stop signal.
pub(crate) struct Supervisor {
    thread: Option<JoinHandle<Outcome>>,
    stop: Option<UnixStream>,
}

impl Supervisor {
    /// Start the supervisor thread with the parent end of the listener
    /// handover socket.
    ///
    /// The thread blocks in `recvmsg` until the forked child sends the
    /// listener, so at the moment of the fork it holds no lock the child
    /// could inherit. That is the same property the forward relay thread
    /// relies on, and it is why `spawn` may stay single-threaded about its
    /// own fork.
    pub(crate) fn start(handover: UnixStream) -> Self {
        let (stop_read, stop_write) = UnixStream::pair().expect("a shutdown pipe");
        let thread = std::thread::Builder::new()
            .name("audit-notify".into())
            .spawn(move || supervise(handover, stop_read))
            .expect("spawning the audit supervisor thread");
        Self {
            thread: Some(thread),
            stop: Some(stop_write),
        }
    }

    /// Signal the supervisor to stop and collect what it recorded.
    ///
    /// Closing the write end is the signal. Abandoned readers are never
    /// joined: shutdown never waits on one.
    pub(crate) fn finish(mut self) -> Outcome {
        drop(self.stop.take());
        self.thread
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default()
    }
}

/// The supervisor loop: receive, read, resolve, continue.
fn supervise(handover: UnixStream, stop: UnixStream) -> Outcome {
    let mut outcome = Outcome::default();
    let listener = match fdpass::recv_fds(&handover, 1, "seccomp listener") {
        Ok(fds) => unsafe { OwnedFd::from_raw_fd(fds[0]) },
        // The child died before arming; the run failed on its own.
        Err(_) => return outcome,
    };
    drop(handover);
    let (notif_size, resp_size) = match notif_sizes() {
        Ok(sizes) => sizes,
        Err(_) => return outcome,
    };
    if notif_size < size_of::<libc::seccomp_notif>() {
        // The kernel's struct is smaller than this build's copy; nothing here
        // can parse it.
        return outcome;
    }
    let mut notif = vec![0u8; notif_size];
    let mut resp = vec![0u8; resp_size];
    let mut reads = Reads::start();
    let mut first = true;
    loop {
        let mut pollfds = [
            pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if pollfds[1].revents != 0 {
            break;
        }
        if pollfds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        // The kernel refuses a RECV whose buffer is not zeroed, to keep the
        // struct extensible, and the previous notification is still in it.
        notif.fill(0);
        if let Err(err) = recv_notification(listener.as_raw_fd(), &mut notif) {
            if err.raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            break;
        }
        // The kernel may size the struct larger than this build's copy; the
        // fields read here are the stable prefix.
        let notification: libc::seccomp_notif =
            unsafe { std::ptr::read_unaligned(notif.as_ptr().cast()) };
        let id = notification.id;
        if !id_valid(listener.as_raw_fd(), id) {
            // The task exited or the syscall was restarted; the notification
            // is stale. Reply anyway, for the interruption case.
            let _ = reply_continue(listener.as_raw_fd(), id, &mut resp);
            continue;
        }
        let step = if reads.blinded {
            Step::Dropped
        } else {
            handle_notification(
                &mut reads,
                notification.pid,
                notification.data.nr as i64,
                notification.data.args,
                first,
            )
        };
        // What the reads brought back is only this notification's to use
        // while it is still live: a target that exited while its memory was
        // being read leaves a pid another process may hold now, so an id
        // that went invalid during the reads discards what they returned.
        let step = match step {
            Step::Recorded(_) if !id_valid(listener.as_raw_fd(), id) => Step::Dropped,
            step => step,
        };
        first = false;
        match step {
            Step::Fatal(message) => {
                outcome.failure = Some(message);
                // Close the listener without replying: the kernel fails the
                // held exec with ENOSYS and the run ends. The observer never
                // chooses an errno.
                break;
            }
            Step::Recorded(event) => {
                if outcome.events.len() >= MAX_EVENTS {
                    outcome.dropped += 1;
                } else {
                    outcome.events.push(event);
                }
            }
            Step::Dropped => outcome.dropped += 1,
            Step::Skipped => {}
        }
        let _ = reply_continue(listener.as_raw_fd(), id, &mut resp);
    }
    if reads.blinded {
        outcome.loss = Some(format!(
            "memory reads stopped after {MAX_ABANDONED_READERS} stalled reads"
        ));
    }
    outcome
}

/// Read a NUL-terminated path out of target memory.
fn read_path(reads: &mut Reads, pid: u32, addr: u64) -> io::Result<PathBuf> {
    let bytes = reads.read(pid, addr, PATH_MAX)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    if end == 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(PathBuf::from(OsString::from_vec(bytes[..end].to_vec())))
}

/// How an open-style path resolves.
enum Resolve {
    /// As the kernel resolves `openat`: absolute as named, relative against
    /// `dirfd` or the working directory.
    Plain,
    /// As the kernel resolves `openat2` under `RESOLVE_IN_ROOT`: joined under
    /// `dirfd` even when absolute.
    InRoot,
}

/// Read the path at `addr` and place it the way the kernel will.
fn resolve_path(
    reads: &mut Reads,
    pid: u32,
    addr: u64,
    dirfd: i64,
    resolve: Resolve,
) -> io::Result<(Resource, Resolution)> {
    let named = read_path(reads, pid, addr)?;
    let path = Path::new(&named);
    if path.is_absolute() {
        if let Resolve::InRoot = resolve {
            return Ok(in_root(pid, dirfd, &named));
        }
        // A lexical absolute path with a `..` component is not the path the
        // kernel accessed, so it is recorded unresolved rather than placed
        // wrong.
        if has_parent_dir(path) {
            return Ok((Resource::Path(named), Resolution::Unresolved));
        }
        return Ok((Resource::Path(named), Resolution::Absolute));
    }
    if let Resolve::InRoot = resolve {
        return Ok(in_root(pid, dirfd, &named));
    }
    match base_directory(pid, dirfd) {
        Some(base) if !has_parent_dir(path) => {
            Ok((Resource::Path(base.join(&named)), Resolution::Userspace))
        }
        _ => Ok((Resource::Path(named), Resolution::Unresolved)),
    }
}

/// Whether a path carries a `..` component.
fn has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component == std::path::Component::ParentDir)
}

/// Place a `RESOLVE_IN_ROOT` path under `dirfd`.
///
/// The kernel clamps a `..` at the root, which a lexical join would not, so a
/// path with a `..` component is recorded as unresolved rather than placed
/// wrong.
fn in_root(pid: u32, dirfd: i64, named: &Path) -> (Resource, Resolution) {
    let stripped = named
        .components()
        .filter(|component| !matches!(component, std::path::Component::RootDir))
        .collect::<PathBuf>();
    if has_parent_dir(&stripped) {
        return (Resource::Path(named.to_path_buf()), Resolution::Unresolved);
    }
    match base_directory(pid, dirfd) {
        Some(base) => (Resource::Path(base.join(stripped)), Resolution::Userspace),
        None => (Resource::Path(named.to_path_buf()), Resolution::Unresolved),
    }
}

/// The directory a relative path resolves against, when it can be read.
fn base_directory(pid: u32, dirfd: i64) -> Option<PathBuf> {
    let link = if dirfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    std::fs::read_link(link).ok()
}

/// Read or write, from an open flags word.
fn access_of(flags: u64) -> AccessKind {
    if flags & O_ACCMODE == O_RDONLY {
        AccessKind::Read
    } else {
        AccessKind::Write
    }
}

fn event(kind: AccessKind, resource: Resource, pid: u32, resolution: Resolution) -> AccessEvent {
    AccessEvent {
        kind,
        resource,
        pid,
        timestamp_ns: now_ns(),
        resolution,
    }
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64).wrapping_mul(1_000_000_000) + ts.tv_nsec as u64
}

/// The message a fatal first-read failure carries.
///
/// The ptrace policy is the cause that matters in practice, and naming it is
/// what the run reports.
fn memory_read_error_message(err: &io::Error) -> String {
    if matches!(err.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) {
        format!(
            "the target's memory could not be read ({err}); a hardened Yama \
             ptrace policy (ptrace_scope 2 or 3) can forbid this, and the \
             fallback observer cannot record without reading the target"
        )
    } else {
        format!(
            "the target's memory could not be read ({err}); the fallback \
             observer cannot record without reading the target, so check the \
             Yama ptrace_scope policy and the target's mappings"
        )
    }
}

/// Turn one notification into a trace step.
///
/// Unreadable arguments are dropped, which marks the trace truncated, except
/// on the first notification: there a failed read is the run's own verdict,
/// because the exec's path is always readable memory and a failure names the
/// ptrace policy instead.
fn handle_notification(reads: &mut Reads, pid: u32, nr: i64, args: [u64; 6], first: bool) -> Step {
    let failed = |err: io::Error| -> Step {
        // A hardened ptrace policy is what stops bailey from reading its own
        // child, and on the first notification that is the run's verdict. A
        // target that simply named an unmapped address only loses one event,
        // which the dropped count reports.
        let ptrace_shaped = matches!(err.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM));
        if first && ptrace_shaped {
            Step::Fatal(memory_read_error_message(&err))
        } else {
            Step::Dropped
        }
    };
    // `open` and `creat` exist only on x86_64; the negative sentinels are
    // never a syscall number, so their arms are unreachable elsewhere.
    #[cfg(target_arch = "x86_64")]
    const OPEN_ARM: i64 = libc::SYS_open;
    #[cfg(not(target_arch = "x86_64"))]
    const OPEN_ARM: i64 = -1;
    #[cfg(target_arch = "x86_64")]
    const CREAT_ARM: i64 = libc::SYS_creat;
    #[cfg(not(target_arch = "x86_64"))]
    const CREAT_ARM: i64 = -2;
    match nr {
        libc::SYS_execve => match resolve_path(reads, pid, args[0], AT_FDCWD, Resolve::Plain) {
            Ok((resource, resolution)) => {
                Step::Recorded(event(AccessKind::Execute, resource, pid, resolution))
            }
            Err(err) => failed(err),
        },
        libc::SYS_execveat => {
            if args[3] & AT_EMPTY_PATH != 0 {
                // The kernel opens the file `dirfd` names; the path argument
                // is ignored.
                return match base_directory_path(pid, args[0] as i64) {
                    Some(path) => Step::Recorded(event(
                        AccessKind::Execute,
                        Resource::Path(path),
                        pid,
                        Resolution::Userspace,
                    )),
                    None => Step::Dropped,
                };
            }
            match resolve_path(reads, pid, args[1], args[0] as i64, Resolve::Plain) {
                Ok((resource, resolution)) => {
                    Step::Recorded(event(AccessKind::Execute, resource, pid, resolution))
                }
                Err(err) => failed(err),
            }
        }
        libc::SYS_openat => match resolve_path(reads, pid, args[1], args[0] as i64, Resolve::Plain)
        {
            Ok((resource, resolution)) => {
                Step::Recorded(event(access_of(args[2]), resource, pid, resolution))
            }
            Err(err) => failed(err),
        },
        OPEN_ARM => match resolve_path(reads, pid, args[0], AT_FDCWD, Resolve::Plain) {
            Ok((resource, resolution)) => {
                Step::Recorded(event(access_of(args[1]), resource, pid, resolution))
            }
            Err(err) => failed(err),
        },
        CREAT_ARM => match resolve_path(reads, pid, args[0], AT_FDCWD, Resolve::Plain) {
            Ok((resource, resolution)) => {
                Step::Recorded(event(AccessKind::Write, resource, pid, resolution))
            }
            Err(err) => failed(err),
        },
        libc::SYS_openat2 => {
            let named = match read_path(reads, pid, args[1]) {
                Ok(named) => named,
                Err(err) => return failed(err),
            };
            let how = match reads.read(pid, args[2], 24) {
                Ok(how) if how.len() == 24 => how,
                Ok(_) => return Step::Dropped,
                Err(err) => return failed(err),
            };
            let flags = u64::from_le_bytes(how[0..8].try_into().expect("eight bytes"));
            let resolve_bits = u64::from_le_bytes(how[16..24].try_into().expect("eight bytes"));
            let kind = access_of(flags);
            if resolve_bits & !KNOWN_RESOLVE_BITS != 0 {
                // The kernel will interpret the path in a way this build
                // cannot describe.
                return Step::Recorded(event(
                    kind,
                    Resource::Path(named),
                    pid,
                    Resolution::Unresolved,
                ));
            }
            let resolve = if resolve_bits & RESOLVE_IN_ROOT != 0 {
                Resolve::InRoot
            } else {
                Resolve::Plain
            };
            match resolve_path(reads, pid, args[1], args[0] as i64, resolve) {
                Ok((resource, resolution)) => {
                    Step::Recorded(event(kind, resource, pid, resolution))
                }
                Err(err) => failed(err),
            }
        }
        libc::SYS_connect => match read_sockaddr(reads, pid, args[1], args[2]) {
            Ok(Some((host, port))) => Step::Recorded(event(
                AccessKind::Connect,
                Resource::Net {
                    host: Some(host),
                    port,
                },
                pid,
                Resolution::NotApplicable,
            )),
            Ok(None) => Step::Skipped,
            Err(err) => failed(err),
        },
        // The filter notifies nothing else; this arm exists so a future
        // syscall added to the filter cannot silently lose its events.
        _ => Step::Skipped,
    }
}
/// The target of a descriptor, when it can be read.
fn base_directory_path(pid: u32, dirfd: i64) -> Option<PathBuf> {
    if dirfd == AT_FDCWD {
        return std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
    }
    std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
}

/// Read a `sockaddr` out of target memory, keeping only TCP families.
///
/// `Ok(None)` is a family the eBPF observer skips too, so nothing is lost.
fn read_sockaddr(
    reads: &mut Reads,
    pid: u32,
    addr: u64,
    len: u64,
) -> io::Result<Option<(String, u16)>> {
    let len = (len as usize).min(28);
    if len < 8 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let bytes = reads.read(pid, addr, len)?;
    if bytes.len() < 4 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let family = u16::from_le_bytes(bytes[0..2].try_into().expect("two bytes"));
    let port = u16::from_be_bytes(bytes[2..4].try_into().expect("two bytes"));
    match family {
        family if family == libc::AF_INET as u16 => {
            if bytes.len() < 8 {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let octets: [u8; 4] = bytes[4..8].try_into().expect("four bytes");
            Ok(Some((Ipv4Addr::from(octets).to_string(), port)))
        }
        family if family == libc::AF_INET6 as u16 => {
            if bytes.len() < 24 {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let octets: [u8; 16] = bytes[8..24].try_into().expect("sixteen bytes");
            Ok(Some((Ipv6Addr::from(octets).to_string(), port)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::Mutex;

    use libc::c_int;

    /// Report a unit test as skipped, mirroring the helper in `audit.rs`:
    /// the same printed line and log shape, keyed by crate and module path.
    fn skip(reason: &str) {
        eprintln!("skipping: {reason}");
        let Some(path) = std::env::var_os("BAILEY_TEST_SKIP_LOG") else {
            return;
        };
        let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        else {
            return;
        };
        use std::io::Write as _;
        let name = std::thread::current();
        let test = name.name().unwrap_or("unknown");
        let _ = writeln!(log, "{}::{}\t{}", env!("CARGO_CRATE_NAME"), test, reason);
    }

    /// The notification machinery needs user notification and a readable
    /// `/proc`, both of which a hardened ptrace policy can take away.
    fn require_fallback() -> bool {
        matches!(
            crate::backend::probe::fallback_status(),
            crate::backend::probe::FallbackStatus::Available
        )
    }

    /// Run `body` in a forked child under the armed filter, and return what
    /// the supervisor recorded. The child arms, runs the body, and exits;
    /// every notification it raises is answered before the wait returns.
    fn supervise_child(body: impl FnOnce()) -> Outcome {
        let _window = SUPERVISE_LOCK.lock().expect("the supervise lock");
        supervise_window(body)
    }

    /// The same, already holding `SUPERVISE_LOCK`.
    fn supervise_window(body: impl FnOnce()) -> Outcome {
        let (parent_end, child_end) = UnixStream::pair().expect("socketpair");
        let supervisor = Supervisor::start(parent_end);
        let handover = child_end.as_raw_fd();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {:?}", io::Error::last_os_error());
        if pid == 0 {
            // In the forked child. Nothing after arm is expected to be
            // allocation-free; the body runs only raw syscalls of its own.
            // Installing a filter needs no_new_privs, exactly as the audit's
            // own pre-exec sets it.
            let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if nnp != 0 || arm(handover).is_err() {
                unsafe { libc::_exit(2) };
            }
            body();
            unsafe { libc::_exit(0) };
        }
        drop(child_end);
        let mut status: c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child failed to arm or run its body: status {status}"
        );
        supervisor.finish()
    }

    /// Assert the run recorded no fatal first-read failure, naming it when
    /// it did.
    fn expect_no_fatal(outcome: &Outcome) {
        assert!(
            outcome.failure.is_none(),
            "the supervisor gave up: {:?}",
            outcome.failure
        );
    }

    /// Execute `/bin/true` the way the kernel would, in the forked child.
    fn child_execve_true() {
        let program = CString::new("/bin/true").expect("a path without NUL");
        let argv = [program.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        unsafe {
            libc::execve(program.as_ptr(), argv.as_ptr().cast(), envp.as_ptr().cast());
        }
    }

    /// A tiny interpreter over the filter, for tests: loads `nr` and `arch`,
    /// compares, returns.
    fn run_filter(nr: i64, arch: u32) -> u32 {
        let program = filter();
        let mut pc = 0usize;
        let mut acc = 0u32;
        loop {
            let instruction = &program[pc];
            match instruction.code {
                BPF_LD_W_ABS => {
                    acc = match instruction.k {
                        NR_OFFSET => nr as u32,
                        ARCH_OFFSET => arch,
                        other => panic!("a load the test does not model: {other}"),
                    };
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc = if acc == instruction.k {
                        pc + 1 + instruction.jt as usize
                    } else {
                        pc + 1 + instruction.jf as usize
                    };
                }
                BPF_RET_K => return instruction.k,
                other => panic!("an instruction the test does not model: {other:#x}"),
            }
        }
    }

    #[test]
    fn the_filter_notifies_only_the_observed_syscalls() {
        for nr in OBSERVED {
            assert_eq!(
                run_filter(nr, NATIVE_AUDIT_ARCH),
                libc::SECCOMP_RET_USER_NOTIF,
                "syscall {nr} is notified"
            );
        }
        assert_eq!(
            run_filter(libc::SYS_getpid, NATIVE_AUDIT_ARCH),
            libc::SECCOMP_RET_ALLOW,
            "an unobserved syscall is allowed"
        );
        assert_eq!(
            run_filter(libc::SYS_openat, 0x8000_0000),
            libc::SECCOMP_RET_ALLOW,
            "a foreign architecture is allowed, for the denylist's errno to win"
        );
    }

    #[test]
    fn the_filter_always_ends_in_allow() {
        let program = filter();
        assert_eq!(
            program.last().map(|last| last.k),
            Some(libc::SECCOMP_RET_ALLOW)
        );
    }

    #[test]
    fn arming_hands_a_listener_to_the_parent() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let (parent_end, child_end) = UnixStream::pair().expect("socketpair");
        let handover = child_end.as_raw_fd();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            drop(parent_end);
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            let armed = arm(handover);
            unsafe { libc::_exit(if armed.is_ok() { 0 } else { 1 }) };
        }
        drop(child_end);
        let fds = fdpass::recv_fds(&parent_end, 1, "seccomp listener")
            .expect("the child hands over the listener");
        assert!(fds[0] >= 0);
        let mut status: c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child armed cleanly: status {status}"
        );
        // Drop the listener in the test process too: keeping it would leave
        // this process observed for its remaining lifetime.
        drop(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        drop(parent_end);
    }

    #[test]
    fn a_stop_before_the_handover_ends_the_supervisor() {
        let (parent_end, child_end) = UnixStream::pair().expect("socketpair");
        drop(child_end);
        let supervisor = Supervisor::start(parent_end);
        let outcome = supervisor.finish();
        assert!(outcome.events.is_empty());
        assert_eq!(outcome.dropped, 0);
        assert!(outcome.failure.is_none());
    }

    #[test]
    fn an_absolute_open_is_recorded() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let outcome = supervise_child(|| {
            let path = CString::new("/etc/hostname").expect("a path without NUL");
            unsafe {
                libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY);
            }
        });
        assert!(!outcome.events.is_empty(), "an open is recorded");
        let opened = outcome
            .events
            .iter()
            .find(|event| event.resource == Resource::Path(PathBuf::from("/etc/hostname")))
            .expect("the opened path appears");
        assert_eq!(opened.kind, AccessKind::Read);
        assert_eq!(opened.resolution, Resolution::Absolute);
        assert!(outcome.dropped == 0, "nothing was dropped");
    }

    #[test]
    fn a_relative_open_is_recorded_userspace() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("target.txt"), "x").expect("a file to open");
        let target = dir.path().join("target.txt");
        let cwd = CString::new(dir.path().to_str().expect("a utf-8 tempdir"))
            .expect("a path without NUL");
        let name = CString::new("target.txt").expect("a path without NUL");
        let outcome = supervise_child(|| unsafe {
            libc::chdir(cwd.as_ptr());
            libc::openat(libc::AT_FDCWD, name.as_ptr(), libc::O_RDONLY);
        });
        let opened = outcome
            .events
            .iter()
            .find(|event| event.resource == Resource::Path(target.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "the relative open resolves against the child's directory: \
                     {} event(s), {} dropped: {:?}",
                    outcome.events.len(),
                    outcome.dropped,
                    outcome.events
                )
            });
        assert_eq!(opened.resolution, Resolution::Userspace);
        assert_eq!(opened.kind, AccessKind::Read);
    }

    /// A relative open naming `..` cannot be placed by joining: the kernel
    /// resolves the `..` where the join does not, so the access is recorded
    /// unresolved rather than under the directory the join names.
    #[test]
    fn a_relative_open_with_dotdot_is_recorded_unresolved() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(dir.path().join("proj")).expect("a directory");
        let cwd = CString::new(dir.path().to_str().expect("a utf-8 tempdir"))
            .expect("a path without NUL");
        let name = CString::new("proj/..").expect("a path without NUL");
        let outcome = supervise_child(|| unsafe {
            libc::chdir(cwd.as_ptr());
            libc::openat(
                libc::AT_FDCWD,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
        });
        let opened = outcome
            .events
            .iter()
            .find(|event| event.resource == Resource::Path(PathBuf::from("proj/..")))
            .expect("the open is recorded as it was named");
        assert_eq!(opened.resolution, Resolution::Unresolved);
    }

    #[test]
    fn an_absolute_openat2_under_in_root_is_joined_under_the_dirfd() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        let dir_path = CString::new(dir.path().to_str().expect("a utf-8 tempdir"))
            .expect("a path without NUL");
        let named = CString::new("/tmp/escape").expect("a path without NUL");
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: RESOLVE_IN_ROOT,
        };
        let outcome = supervise_child(|| unsafe {
            let dirfd = libc::open(dir_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                named.as_ptr(),
                &how as *const OpenHow,
                24usize,
            );
        });
        expect_no_fatal(&outcome);
        // The host path /tmp/escape must not appear: under RESOLVE_IN_ROOT the
        // kernel resolves it inside the directory the descriptor names.
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.resource != Resource::Path(PathBuf::from("/tmp/escape"))),
            "the host path is never recorded"
        );
        let joined = outcome
            .events
            .iter()
            .find(|event| event.resource == Resource::Path(dir.path().join("tmp/escape")))
            .expect("the path is joined under the descriptor's directory");
        assert_eq!(joined.resolution, Resolution::Userspace);
    }

    #[test]
    fn a_parent_component_under_in_root_is_unresolved() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        let dir_path = CString::new(dir.path().to_str().expect("a utf-8 tempdir"))
            .expect("a path without NUL");
        let named = CString::new("../outside").expect("a path without NUL");
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: RESOLVE_IN_ROOT,
        };
        let outcome = supervise_child(|| unsafe {
            let dirfd = libc::open(dir_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                named.as_ptr(),
                &how as *const OpenHow,
                24usize,
            );
        });
        expect_no_fatal(&outcome);
        let unresolved = outcome
            .events
            .iter()
            .find(|event| event.resolution == Resolution::Unresolved)
            .expect("a .. under RESOLVE_IN_ROOT is unresolved");
        assert_eq!(
            unresolved.resource,
            Resource::Path(PathBuf::from("../outside"))
        );
    }

    #[test]
    fn an_openat2_with_only_restrict_flags_records_as_for_openat() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("target.txt"), "x").expect("a file to open");
        let target = dir.path().join("target.txt");
        let dir_path = CString::new(dir.path().to_str().expect("a utf-8 tempdir"))
            .expect("a path without NUL");
        let named = CString::new("target.txt").expect("a path without NUL");
        // RESOLVE_BENEATH (0x08) restricts the lookup without moving it.
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 0x08,
        };
        let outcome = supervise_child(|| unsafe {
            let dirfd = libc::open(dir_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                named.as_ptr(),
                &how as *const OpenHow,
                24usize,
            );
        });
        expect_no_fatal(&outcome);
        let opened = outcome
            .events
            .iter()
            .find(|event| event.resource == Resource::Path(target.clone()))
            .expect("the restricted lookup records like an openat");
        assert_eq!(opened.resolution, Resolution::Userspace);
    }

    #[test]
    fn an_openat2_with_an_unknown_resolve_bit_is_unresolved() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let named = CString::new("/etc/hostname").expect("a path without NUL");
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 1 << 30,
        };
        let outcome = supervise_child(|| unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                named.as_ptr(),
                &how as *const OpenHow,
                24usize,
            );
        });
        let unresolved = outcome
            .events
            .iter()
            .find(|event| event.resolution == Resolution::Unresolved)
            .expect("an unknown resolve bit is unresolved");
        assert_eq!(unresolved.kind, AccessKind::Read);
    }

    #[test]
    fn an_exec_is_recorded_and_carries_the_target() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let outcome = supervise_child(child_execve_true);
        let executed = outcome
            .events
            .iter()
            .find(|event| event.kind == AccessKind::Execute)
            .expect("the exec is recorded");
        assert!(
            matches!(&executed.resource, Resource::Path(path) if path.ends_with("true")),
            "the executed program is named: {:?}",
            executed.resource
        );
    }

    #[test]
    fn a_loopback_connect_is_recorded_on_both_families() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let mut v4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        v4.sin_family = libc::AF_INET as libc::sa_family_t;
        v4.sin_port = 9u16.to_be();
        v4.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let outcome = supervise_child(|| unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            libc::connect(
                fd,
                (&raw const v4).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_in>() as u32,
            );
            libc::close(fd);
        });
        let connected = outcome
            .events
            .iter()
            .find(|event| event.kind == AccessKind::Connect)
            .expect("the IPv4 connect is recorded");
        assert_eq!(
            connected.resource,
            Resource::Net {
                host: Some("127.0.0.1".into()),
                port: 9,
            }
        );

        let mut v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        v6.sin6_port = 9u16.to_be();
        v6.sin6_addr = libc::in6_addr {
            // ::1
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        let outcome = supervise_child(|| unsafe {
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            libc::connect(
                fd,
                (&raw const v6).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_in6>() as u32,
            );
            libc::close(fd);
        });
        let connected = outcome
            .events
            .iter()
            .find(|event| event.kind == AccessKind::Connect)
            .expect("the IPv6 connect is recorded");
        assert_eq!(
            connected.resource,
            Resource::Net {
                host: Some("::1".into()),
                port: 9,
            }
        );
    }

    #[test]
    fn an_unreadable_pointer_is_dropped() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let outcome = supervise_child(|| unsafe {
            // The first page of the address space is never mapped.
            libc::openat(
                libc::AT_FDCWD,
                0x1000usize as *const libc::c_char,
                libc::O_RDONLY,
            );
        });
        assert!(
            outcome.events.is_empty(),
            "nothing was recorded for the unreadable path: {:?}",
            outcome.events
        );
        assert_eq!(outcome.dropped, 1, "the unreadable access is counted");
        assert!(outcome.failure.is_none());
    }

    /// An id that goes invalid while the reads run discards what they
    /// brought back: the reads may have happened after the target exited
    /// and its pid was reused, and another process's memory is not this
    /// run's trace.
    /// One supervise window at a time. `TEST_EXPIRE_IDS` is global to the
    /// process, so the test that sets it must not overlap a run whose
    /// supervisors consult it.
    static SUPERVISE_LOCK: Mutex<()> = Mutex::new(());

    /// Run one supervise window with the id-expiry hook on, holding the
    /// lock across the flag.
    fn supervise_expired(body: impl FnOnce()) -> Outcome {
        let _window = SUPERVISE_LOCK.lock().expect("the supervise lock");
        TEST_EXPIRE_IDS.store(true, Ordering::SeqCst);
        let outcome = supervise_window(body);
        TEST_EXPIRE_IDS.store(false, Ordering::SeqCst);
        outcome
    }

    #[test]
    fn a_notification_that_dies_during_the_read_loses_its_event() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let outcome = supervise_expired(|| unsafe {
            let path = CString::new("/etc/hostname").expect("a path without NUL");
            libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY);
        });
        expect_no_fatal(&outcome);
        assert!(
            outcome.events.is_empty(),
            "nothing was recorded for the expired notification: {:?}",
            outcome.events
        );
        assert_eq!(outcome.dropped, 1, "the expired access is counted");
    }

    #[test]
    fn a_fatal_first_read_names_the_ptrace_policy() {
        if !require_fallback() {
            skip("the fallback observer is unavailable on this host");
            return;
        }
        let message = memory_read_error_message(&io::Error::from_raw_os_error(libc::EACCES));
        assert!(message.contains("ptrace_scope"), "{message}");
        assert!(
            message.contains("cannot record"),
            "the message says what was lost: {message}"
        );
    }

    /// `openat2`'s argument struct, laid out as the kernel defines it.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
}
