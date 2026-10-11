//! Host TCP ports carried onto the sandbox's own loopback.
//!
//! The target sits in a network namespace with nothing listening, and dials
//! `127.0.0.1:port` the way a client library dials a local daemon. Bailey
//! carries that connection to the host, where the real service runs. The
//! namespace keeps its edge: no route to the host stack exists except the
//! ports this policy names.
//!
//! The mechanism is one file descriptor crossing the namespace boundary. A
//! socket keeps the namespace it was bound in for life, so the sandbox side
//! binds the listener while the namespace is active and hands it to bailey
//! over a socketpair before exec. Bailey then accepts on a listener that
//! lives inside the target's network namespace while dialing the host from
//! outside it.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::thread;

use crate::policy::PortForward;

/// Bind the forward listeners from inside the sandbox and hand them over.
///
/// Runs in `pre_exec`, after the network namespace exists and before any
/// policy applies. The listeners are created with close-on-exec, so the
/// sandbox's own copies vanish at exec; the only surviving handles are the
/// ones the parent receives. On failure the error propagates out of
/// `pre_exec` and the spawn fails with the bind error, for example when a
/// forward port collides with one the policy already listens on.
pub(crate) fn arm(announce: RawFd, forwards: &[PortForward]) -> io::Result<()> {
    if forwards.is_empty() {
        return Ok(());
    }
    let mut fds = Vec::with_capacity(forwards.len());
    let result = bind_all(&mut fds, forwards).and_then(|()| send_fds(announce, &fds));
    if result.is_err() {
        for fd in fds {
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    result
}

fn bind_all(fds: &mut Vec<RawFd>, forwards: &[PortForward]) -> io::Result<()> {
    for forward in forwards {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, forward.port))?;
        fds.push(listener.into_raw_fd());
    }
    Ok(())
}

/// The forwards of one run: listeners on the sandbox's loopback, carried to
/// the host for as long as the run lives.
pub(crate) struct ForwardGuard {
    listeners: Vec<(TcpListener, u16)>,
}

impl ForwardGuard {
    /// Take the listeners the sandbox handed over, paired with their host
    /// destinations in policy order.
    pub(crate) fn receive(
        stream: &std::os::unix::net::UnixStream,
        forwards: &[PortForward],
    ) -> io::Result<Self> {
        if forwards.is_empty() {
            return Ok(Self {
                listeners: Vec::new(),
            });
        }
        // Wait for readability in bounded slices rather than one blocking
        // read: a wake-up that never comes would hang the relay for the
        // whole run, and the send always arrives while the sandbox lives or
        // not at all, so re-checking costs nothing.
        loop {
            let mut pollfds = [libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), 1, 250) };
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if ready > 0 || pollfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
        }
        let fds = recv_fds(stream, forwards.len())?;
        let listeners = fds
            .into_iter()
            .zip(forwards)
            .map(|(fd, forward)| {
                let listener = unsafe { TcpListener::from_raw_fd(fd) };
                (listener, forward.host_port)
            })
            .collect();
        Ok(Self { listeners })
    }

    /// Serve every forwarded port until the run ends.
    ///
    /// Each port gets one thread of its own, and that thread carries its
    /// connections one at a time: a desktop daemon holds a connection per
    /// client, and a queued second client waits in the listen backlog until
    /// the first is done. The host side is dialed fresh per connection, so a
    /// service that restarts underneath a running sandbox keeps working.
    pub(crate) fn serve(&self) {
        for (listener, host_port) in &self.listeners {
            let Ok(acceptor) = listener.try_clone() else {
                continue;
            };
            let host_port = *host_port;
            thread::spawn(move || {
                for client in acceptor.incoming().flatten() {
                    let Ok(service) = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)) else {
                        // No host service on this port right now. The client
                        // sees a closed connection instead of a hang, which
                        // is what dialing a dead local daemon looks like.
                        continue;
                    };
                    pump(client, service);
                }
            });
        }
    }
}

/// Stop reading on one side once its queue holds this much.
const HIGH_WATER: usize = 256 * 1024;

/// Read more bytes into `buf` without blocking.
///
/// Returns whether the far end is still sending. An end that sent its last
/// byte reads as `Ok(0)`, which is what turns into a half-close downstream.
fn fill(stream: &TcpStream, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut stream = stream;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if buf.len() >= HIGH_WATER {
            return Ok(true);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(true),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

/// Pour what was read into the far end without blocking.
///
/// Returns whether everything buffered was accepted. Bytes the kernel refused
/// stay buffered for the next round.
fn drain(stream: &TcpStream, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut stream = stream;
    loop {
        if buf.is_empty() {
            return Ok(true);
        }
        match stream.write(buf) {
            Ok(n) => {
                buf.drain(..n);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

/// Carry one connection in both directions on one thread.
///
/// Both ends are nonblocking and `poll` drives them. Each direction
/// propagates the end it sees: when the client stops writing, the service
/// learns the request is complete once the last buffered byte is through,
/// and the other way around. A broken direction ends the connection; there
/// is no caller left to report to.
fn pump(client: TcpStream, service: TcpStream) {
    for stream in [&client, &service] {
        let _ = stream.set_nonblocking(true);
    }
    let mut to_service: Vec<u8> = Vec::new();
    let mut to_client: Vec<u8> = Vec::new();
    let mut client_sends = true;
    let mut service_sends = true;
    let mut pollfds = [
        libc::pollfd {
            fd: client.as_raw_fd(),
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: service.as_raw_fd(),
            events: 0,
            revents: 0,
        },
    ];
    loop {
        pollfds[0].events = 0;
        pollfds[1].events = 0;
        if client_sends && to_service.len() < HIGH_WATER {
            pollfds[0].events |= libc::POLLIN;
        }
        if !to_client.is_empty() {
            pollfds[0].events |= libc::POLLOUT;
        }
        if service_sends && to_client.len() < HIGH_WATER {
            pollfds[1].events |= libc::POLLIN;
        }
        if !to_service.is_empty() {
            pollfds[1].events |= libc::POLLOUT;
        }
        if pollfds[0].events == 0 && pollfds[1].events == 0 {
            // Both ends are spent and everything read was delivered.
            return;
        }
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let client_event = pollfds[0].revents;
        let service_event = pollfds[1].revents;
        if client_event & libc::POLLIN != 0 {
            match fill(&client, &mut to_service) {
                Ok(still_sending) => client_sends = still_sending,
                Err(_) => return,
            }
        }
        if service_event & libc::POLLIN != 0 {
            match fill(&service, &mut to_client) {
                Ok(still_sending) => service_sends = still_sending,
                Err(_) => return,
            }
        }
        if client_event & libc::POLLOUT != 0 {
            match drain(&client, &mut to_client) {
                Ok(_) => {}
                Err(_) => return,
            }
        }
        if service_event & libc::POLLOUT != 0 {
            match drain(&service, &mut to_service) {
                Ok(_) => {}
                Err(_) => return,
            }
        }
        // Each direction ends when its far end stopped sending and everything
        // read was delivered. Checked outside the POLLOUT branches: a queue
        // that drained in the same round never raises POLLOUT again, and the
        // end must still propagate.
        if !client_sends && to_service.is_empty() {
            let _ = service.shutdown(std::net::Shutdown::Write);
        }
        if !service_sends && to_client.is_empty() {
            let _ = client.shutdown(std::net::Shutdown::Write);
        }
        if client_event & (libc::POLLERR | libc::POLLNVAL) != 0
            || service_event & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return;
        }
    }
}

/// Send file descriptors to the parent over the announce socket.
fn send_fds(announce: RawFd, fds: &[RawFd]) -> io::Result<()> {
    let payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let space = cmsg_space(fds.len());
    let mut control = vec![0u8; space];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_controllen = space as _;
    message.msg_control = control.as_mut_ptr().cast();
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((size_of_val(fds)) as _) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            fds.len(),
        );
        if libc::sendmsg(announce, &message, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive the handover from the sandbox, closing everything on a short read.
fn recv_fds(stream: &std::os::unix::net::UnixStream, count: usize) -> io::Result<Vec<RawFd>> {
    use std::os::fd::AsRawFd;
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let space = cmsg_space(count);
    let mut control = vec![0u8; space];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_controllen = space as _;
    message.msg_control = control.as_mut_ptr().cast();
    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 {
        // The sandbox died or never armed; every received descriptor in the
        // queue was closed by the kernel, so there is nothing to clean up.
        return Err(io::Error::other(
            "the sandbox closed before handing over the forward listeners",
        ));
    }
    let mut fds = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let items = bytes / size_of::<RawFd>();
                let source = libc::CMSG_DATA(header).cast_const().cast::<RawFd>();
                for item in 0..items {
                    fds.push(*source.add(item));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if fds.len() != count {
        for fd in &fds {
            drop(unsafe { OwnedFd::from_raw_fd(*fd) });
        }
        return Err(io::Error::other(format!(
            "the sandbox handed over {} of {count} forward listeners",
            fds.len()
        )));
    }
    Ok(fds)
}

fn cmsg_space(count: usize) -> usize {
    unsafe { libc::CMSG_SPACE((count * size_of::<RawFd>()) as _) as usize }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// A free loopback port, racy until bound again but fine for tests.
    fn free_port() -> u16 {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn descriptors_survive_the_announce_roundtrip() {
        use std::os::fd::AsRawFd;
        let (announce, child_end) = UnixStream::pair().unwrap();
        let (mut kept, traveled) = UnixStream::pair().unwrap();
        let raw = traveled.into_raw_fd();
        let sender = thread::spawn(move || send_fds(child_end.as_raw_fd(), &[raw]).unwrap());
        let back = recv_fds(&announce, 1).unwrap();
        sender.join().unwrap();
        assert_eq!(back.len(), 1);
        let mut far_end = unsafe { UnixStream::from_raw_fd(back[0]) };
        far_end.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        kept.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// Three descriptors through the same handover. The receive side walks the
    /// control message and counts the descriptors its length implies, so this
    /// is the case where a wrong count or a wrong stride stops being
    /// indistinguishable from the single-descriptor one.
    #[test]
    fn several_descriptors_survive_the_announce_roundtrip() {
        use std::os::fd::AsRawFd;
        let (announce, child_end) = UnixStream::pair().unwrap();
        let mut kept = Vec::new();
        let mut raw = Vec::new();
        for _ in 0..3 {
            let (keep, traveled) = UnixStream::pair().unwrap();
            raw.push(traveled.into_raw_fd());
            kept.push(keep);
        }
        let sender = thread::spawn(move || send_fds(child_end.as_raw_fd(), &raw).unwrap());
        let back = recv_fds(&announce, 3).unwrap();
        sender.join().unwrap();
        assert_eq!(back.len(), 3);
        // Each descriptor must be the one it was sent as, not merely present:
        // a stride that preserves the count still lands the wrong far end.
        for (far, mut near) in back.into_iter().zip(kept) {
            let mut far = unsafe { UnixStream::from_raw_fd(far) };
            far.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            near.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
        }
    }

    /// The descriptor count the length implies, without a send: this is the
    /// arithmetic `recv_fds` does, read on a buffer the test controls.
    #[test]
    fn the_control_buffer_holds_the_declared_length() {
        for count in 1..=8 {
            let payload = count * size_of::<RawFd>();
            let buffer = cmsg_space(count);
            let declared = unsafe { libc::CMSG_LEN(payload as _) as usize };
            assert!(
                buffer >= declared,
                "the buffer for {count} descriptors is {buffer} bytes, the \
                 declared control message needs {declared}"
            );
        }
    }

    /// The full round trip without a sandbox: the sandbox side arms and hands
    /// its listener over, the parent serves it, and a client dials the forward
    /// and reaches the host echo.
    #[test]
    fn arm_binds_and_the_parent_carries_to_the_host() {
        let forward_port = free_port();
        let host_port = free_port();
        let host = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, host_port)).unwrap();
        let echoes = thread::spawn(move || {
            // One echo, then done: the thread must end for the test to end.
            let (mut client, _) = host.accept().unwrap();
            let mut buf = [0u8; 2];
            if let Ok(n) = client.read(&mut buf) {
                let _ = client.write_all(&buf[..n]);
            }
        });
        let forwards = vec![PortForward {
            port: forward_port,
            host_port,
        }];
        let (announce, child_end) = UnixStream::pair().unwrap();
        let child_fd = child_end.into_raw_fd();
        let worker = {
            let forwards = forwards.clone();
            thread::spawn(move || arm(child_fd, &forwards).unwrap())
        };
        let guard = ForwardGuard::receive(&announce, &forwards).unwrap();
        worker.join().unwrap();
        guard.serve();
        // The sandbox side holds the port now, so a second bind must fail.
        assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, forward_port)).is_err());
        // Dialing it lands on the handed-over listener, like the target would,
        // and the pump carries it to the echo.
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, forward_port)).unwrap();
        client.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        drop(client);
        echoes.join().ok();
    }

    #[test]
    fn empty_forwards_arm_and_receive_as_nothing() {
        let (announce, child_end) = UnixStream::pair().unwrap();
        let child_fd = child_end.into_raw_fd();
        thread::spawn(move || arm(child_fd, &[]).unwrap());
        let guard = ForwardGuard::receive(&announce, &[]).unwrap();
        assert!(guard.listeners.is_empty());
    }

    /// Split writes must arrive whole, and a half-close must reach the other
    /// side instead of leaving both ends waiting.
    #[test]
    fn the_pump_carries_split_writes_and_half_closes() {
        let target_side = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let service_side = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

        let target = TcpStream::connect((
            Ipv4Addr::LOCALHOST,
            target_side.local_addr().unwrap().port(),
        ))
        .unwrap();
        let (mut peer_of_target, _) = target_side.accept().unwrap();
        let service = TcpStream::connect((
            Ipv4Addr::LOCALHOST,
            service_side.local_addr().unwrap().port(),
        ))
        .unwrap();
        let (mut peer_of_service, _) = service_side.accept().unwrap();

        thread::spawn(move || pump(target, service));

        peer_of_service
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        // Two writes with a pause arrive as the bytes they were, in order.
        peer_of_target.write_all(b"hel").unwrap();
        thread::sleep(std::time::Duration::from_millis(20));
        peer_of_target.write_all(b"lo").unwrap();
        peer_of_target.shutdown(std::net::Shutdown::Write).unwrap();
        let mut whole = Vec::new();
        peer_of_service.read_to_end(&mut whole).unwrap();
        assert_eq!(whole, b"hello");
    }
}
