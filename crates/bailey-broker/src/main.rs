//! The built-in HTTP egress broker.
//!
//! bailey spawns this binary beside the sandbox with the namespaced listener
//! on descriptor 3, the log on descriptor 4, its configuration on stdin, and
//! its own pid as the only argument. The broker confines itself, answers
//! one ready line on stdout,
//! and then serves the CONNECT ACL and HTTP rules the configuration carries.

use std::io::{self, Write};
use std::net::TcpListener;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use bailey_broker::audit::AuditLog;
use bailey_broker::{tls, tunnel};

/// How many connections may be served at once. An agent opens
/// tens, not thousands; a client over the cap is refused with 503.
const MAX_CONNECTIONS: usize = 64;

/// The write end of the self-pipe SIGTERM goes through. The handler does
/// nothing but write one byte, which is async-signal-safe.
static TERM_PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sigterm(_: libc::c_int) {
    let fd = TERM_PIPE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = b"t";
        unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    }
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // A version query is answered before anything is armed or refused: it
    // comes from a doctor that only wants to know what is beside it.
    if std::env::args().any(|arg| arg == "--version") {
        println!(
            "bailey-broker {} (protocol {})",
            env!("CARGO_PKG_VERSION"),
            bailey::broker::BROKER_PROTOCOL_VERSION
        );
        return 0;
    }
    // The death signal is armed before anything else, so a parent that dies
    // is always followed. Then the pid bailey passed is the
    // only argument, and a broker whose parent is not that pid was orphaned
    // before it could arm the signal, or was started by something else, and
    // refuses both.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        eprintln!(
            "bailey-broker: prctl(PR_SET_PDEATHSIG): {}",
            io::Error::last_os_error()
        );
        return 1;
    }
    let expected: u32 = match std::env::args().nth(1).and_then(|arg| arg.parse().ok()) {
        Some(pid) => pid,
        None => {
            eprintln!("usage: bailey-broker <parent-pid>");
            return 2;
        }
    };
    if unsafe { libc::getppid() } != expected as libc::pid_t {
        return 1;
    }
    // Nothing bailey happened to inherit, such as a caller's session bus
    // socket, reaches the broker: everything above 4 goes.
    if let Err(error) = close_descriptors_above_four() {
        eprintln!("bailey-broker: close_range: {error}");
        return 1;
    }
    // What is held after the close. Read before the process is made
    // non-dumpable, because a non-dumpable process's /proc entries are
    // root's, its own included.
    let descriptors = open_descriptors();

    // A dumpable broker would leave its memory, credentials included, in a
    // core file; no_new_privs is also what seccomp and Landlock demand.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        eprintln!(
            "bailey-broker: prctl(PR_SET_DUMPABLE): {}",
            io::Error::last_os_error()
        );
        return 1;
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        eprintln!(
            "bailey-broker: prctl(PR_SET_NO_NEW_PRIVS): {}",
            io::Error::last_os_error()
        );
        return 1;
    }

    // The configuration arrives as one JSON document on stdin, to EOF.
    // Nothing else is trusted: arguments and environment carry no secrets.
    let config = match bailey::broker::BrokerConfig::decode(&mut io::stdin().lock()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bailey-broker: {error}");
            return 1;
        }
    };

    // The interception CA is generated before confinement, where it needs
    // no grant: its key lives in memory only. A run that
    // intercepts nothing carries no CA.
    let authority = if config.http.intercept.is_empty() {
        None
    } else {
        // An intercepting broker verifies upstream certificates against the
        // host's roots, so the roots are read before confinement: after it,
        // whether the load succeeds depends on which paths the loader probes
        // and which grants happen to cover them, and a failure would surface
        // mid-serve instead of refusing the run at startup.
        if let Err(error) = tls::upstream_config() {
            eprintln!("bailey-broker: the host's trust roots: {error}");
            return 1;
        }
        match tls::CertificateAuthority::generate(&config.http.intercept) {
            Ok(authority) => Some(authority),
            Err(error) => {
                eprintln!("bailey-broker: the interception CA: {error}");
                return 1;
            }
        }
    };

    let layers = match bailey::backend::enforce::confine_broker(&config.http) {
        Ok(layers) => layers,
        Err(error) => {
            eprintln!("bailey-broker: confinement: {error}");
            return 1;
        }
    };

    let ready = bailey::broker::BrokerReady {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        ca_pem: authority.as_ref().map(|ca| ca.certificate_pem()),
        layers,
    };
    if let Err(error) = ready.write_to(&mut io::stdout().lock()) {
        eprintln!("bailey-broker: {error}");
        return 1;
    }

    // The test hook: after confinement, attempt what the broker must not be
    // able to do, and print one `probe <name>=<ok|errno N>` line per
    // attempt. Only tests set this.
    if std::env::var_os("BAILEY_BROKER_SELFTEST").is_some() {
        run_selftest_probes(&descriptors);
        return 0;
    }

    // Descriptor 3 is the namespaced listener; descriptor 4 is the
    // append-only log the caller opened and verified. Without the log the
    // decisions still serve, and the counts line still tells the parent
    // how the run went.
    let listener = unsafe { TcpListener::from_raw_fd(3) };
    let log_file = config.log.then(|| unsafe { std::fs::File::from_raw_fd(4) });
    let audit = Arc::new(AuditLog::new(log_file));
    let config = Arc::new(config);
    let authority = Arc::new(authority);
    let serving = Arc::new(AtomicUsize::new(0));

    // SIGTERM is turned into a clean stop through a self-pipe: the
    // handler writes one byte, and the serve loop below polls the pipe
    // beside the listener. The signal is not asked to restart syscalls,
    // so nothing blocks past a wake-up.
    // The read end is nonblocking, so the drain after the wake-up cannot
    // block on an empty pipe whose write end is still open.
    let mut pipe_fds = [-1 as libc::c_int; 2];
    let pipe_flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), pipe_flags) } != 0 {
        eprintln!("bailey-broker: pipe: {}", io::Error::last_os_error());
        return 1;
    }
    let (term_read, term_write) = (pipe_fds[0], pipe_fds[1]);
    TERM_PIPE.store(term_write, Ordering::Relaxed);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_sigterm as *const () as usize;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) } != 0 {
        eprintln!(
            "bailey-broker: sigaction(SIGTERM): {}",
            io::Error::last_os_error()
        );
        return 1;
    }

    if let Err(error) = listener.set_nonblocking(true) {
        if error.raw_os_error() == Some(libc::EBADF) {
            // The descriptor does not exist: nothing can be served, and
            // dropping the listener would close a descriptor std believes
            // it owns, so it is forgotten instead.
            std::mem::forget(listener);
        }
        eprintln!("bailey-broker: the listener is unusable: {error}");
        return 1;
    }
    let mut watched = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: term_read,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        watched.iter_mut().for_each(|entry| entry.revents = 0);
        let ready = unsafe { libc::poll(watched.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                eprintln!("bailey-broker: poll: {error}");
                return 1;
            }
            continue;
        }
        if watched[1].revents & libc::POLLIN != 0 {
            // The parent asked for a stop. Drain the pipe so a second
            // signal finds no stale byte; nonblocking, so an empty pipe
            // answers EAGAIN instead of blocking.
            let mut drain = [0u8; 64];
            loop {
                let read = unsafe { libc::read(term_read, drain.as_mut_ptr().cast(), drain.len()) };
                if read <= 0 {
                    break;
                }
            }
            break;
        }
        if watched[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) => match error.raw_os_error() {
                // Spurious wake-ups are ordinary; serve on.
                Some(libc::EAGAIN | libc::ECONNABORTED) => continue,
                // The descriptor does not exist: nothing can be served, and
                // dropping the listener would close a descriptor std
                // believes it owns, so it is forgotten instead.
                Some(libc::EBADF) => {
                    std::mem::forget(listener);
                    eprintln!("bailey-broker: the listener is unusable: {error}");
                    return 1;
                }
                // The descriptor is open, but not a listening socket:
                // nothing can be served, and retrying would only spin.
                Some(libc::ENOTSOCK | libc::EINVAL | libc::EOPNOTSUPP) => {
                    eprintln!("bailey-broker: the listener is unusable: {error}");
                    return 1;
                }
                // Out of descriptors or memory: back off, then serve on.
                Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                _ => continue,
            },
        };
        if serving.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            // Over the cap the client gets a 503 and nothing is logged:
            // the cap is not a decision about a host, and a flood would
            // fill the log with nothing a run could act on.
            refuse_over_cap(stream);
            continue;
        }
        serving.fetch_add(1, Ordering::Relaxed);
        let config_for_thread = Arc::clone(&config);
        let authority_for_thread = Arc::clone(&authority);
        let audit_for_thread = Arc::clone(&audit);
        let serving_for_thread = Arc::clone(&serving);
        let spawned = std::thread::Builder::new()
            .name("broker-tunnel".into())
            .spawn(move || {
                tunnel::handle_connection(
                    stream,
                    &config_for_thread,
                    &authority_for_thread,
                    &audit_for_thread,
                );
                serving_for_thread.fetch_sub(1, Ordering::Relaxed);
            });
        if spawned.is_err() {
            serving.fetch_sub(1, Ordering::Relaxed);
        }
    }

    // The counts line is the broker's last output, and the parent reads it
    // for the summary it prints after its own.
    {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{}", audit.counts_line());
        let _ = stdout.flush();
    }
    0
}

/// Answer a client over the connection cap with 503 and close.
fn refuse_over_cap(stream: std::net::TcpStream) {
    use std::io::Write;
    let mut stream = stream;
    let _ = stream.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Close every descriptor above 4.
///
/// `close_range` does this in one call; a kernel without it gets the same
/// result by walking `/proc/self/fd`. The directory's own descriptor is
/// skipped, and the closing happens after the listing is complete.
fn close_descriptors_above_four() -> io::Result<()> {
    // Through the syscall rather than libc's wrapper, which musl's bindings
    // do not carry; the syscall number is the same everywhere.
    unsafe {
        if libc::syscall(libc::SYS_close_range, 5u32, u32::MAX, 0u32) == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(error);
        }
    }
    let mut to_close = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let name = entry.file_name();
        let Ok(fd) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        if fd <= 4 {
            continue;
        }
        if entry.path() == std::path::Path::new("/proc/self/fd") {
            continue;
        }
        to_close.push(fd);
    }
    for fd in to_close {
        unsafe { libc::close(fd as i32) };
    }
    Ok(())
}

/// One confinement probe: `ok` when it unexpectedly succeeded, otherwise
/// the kernel's answer.
fn probe_result(result: io::Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => match error.raw_os_error() {
            Some(errno) => format!("errno {errno}"),
            None => format!("error {error}"),
        },
    }
}

/// The descriptors this process holds, sorted and deduplicated.
fn open_descriptors() -> Vec<u32> {
    let mut descriptors: Vec<u32> = std::fs::read_dir("/proc/self/fd")
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default();
    descriptors.sort_unstable();
    descriptors.dedup();
    descriptors
}

/// Attempt what confinement must refuse, and print the results.
fn run_selftest_probes(descriptors: &[u32]) {
    println!(
        "probe inet-socket={}",
        probe_result(unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                libc::close(fd);
                Ok(())
            }
        })
    );

    if let Some(path) = std::env::var_os("BAILEY_BROKER_SELFTEST_UNIX_PATH") {
        println!("probe unix-path={}", probe_result(connect_unix_path(&path)));
    }
    if let Ok(name) = std::env::var("BAILEY_BROKER_SELFTEST_UNIX_ABSTRACT") {
        println!(
            "probe unix-abstract={}",
            probe_result(connect_unix_abstract(&name))
        );
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let probe_file = format!("{home}/.bailey-selftest-probe");
    println!(
        "probe home={}",
        probe_result(std::fs::read_to_string(&probe_file).map(|_| ()))
    );

    if let Ok(address) = std::env::var("BAILEY_BROKER_SELFTEST_TCP_ADDR") {
        println!("probe tcp-connect={}", probe_result(connect_tcp(&address)));
    }

    // The host's trust roots: readable before confinement, and only as
    // readable as the file grants allow after it.
    println!(
        "probe trust-roots={}",
        probe_result(
            crate::tls::upstream_config()
                .map(|_| ())
                .map_err(|error| io::Error::other(error.to_string()))
        )
    );

    // What this process kept after the close: the descriptors the broker
    // lives on, and nothing else.
    let held = descriptors
        .iter()
        .map(|fd| fd.to_string())
        .collect::<Vec<_>>()
        .join(",");
    println!("probe descriptors={held}");
}

/// Connect to a UNIX socket at `path`.
fn connect_unix_path(path: &std::ffi::OsStr) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = path.as_encoded_bytes();
    let len = bytes.len().min(address.sun_path.len() - 1);
    address.sun_path[..len]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), len) });
    let result = unsafe {
        libc::connect(
            fd,
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    let result = if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    unsafe { libc::close(fd) };
    result
}

/// Connect to an abstract UNIX socket named `name`.
fn connect_unix_abstract(name: &str) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = name.as_bytes();
    let len = bytes.len().min(address.sun_path.len() - 1);
    address.sun_path[1..=len]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), len) });
    let address_len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + len) as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            fd,
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            address_len,
        )
    };
    let result = if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    unsafe { libc::close(fd) };
    result
}

/// Connect to a TCP `host:port` address given as an IPv4 literal.
fn connect_tcp(address: &str) -> io::Result<()> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| io::Error::other(format!("the probe address `{address}` has no port")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::other(format!("the probe port `{port}` is not a port")))?;

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let octets: Option<[u8; 4]> = host
        .split('.')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()
        .and_then(|parts| <[u8; 4]>::try_from(parts).ok());
    let Some(octets) = octets else {
        unsafe { libc::close(fd) };
        return Err(io::Error::other(format!(
            "the probe address `{host}` is not an IPv4 literal"
        )));
    };
    let socket_address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(octets),
        },
        sin_zero: [0; 8],
    };
    let result = unsafe {
        libc::connect(
            fd,
            &socket_address as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    let result = if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    unsafe { libc::close(fd) };
    result
}
