//! Passing file descriptors over a Unix socket.
//!
//! Two handovers need the same `SCM_RIGHTS` shape: the forward listeners the
//! sandbox binds in its network namespace, and the seccomp listener the
//! forked child arms and sends to the audit supervisor. Both send one byte
//! of payload with the descriptors in the control message, and both receive
//! with `MSG_CMSG_CLOEXEC`, so a descriptor that lands anywhere has the
//! close-on-exec flag from birth.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// Send file descriptors over an already-connected socket.
pub(crate) fn send_fds(stream: RawFd, fds: &[RawFd]) -> io::Result<()> {
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
        if libc::sendmsg(stream, &message, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive file descriptors, closing everything on a short read.
///
/// `what` names the descriptors in errors, so each caller's message says what
/// it was waiting for.
pub(crate) fn recv_fds(
    stream: &std::os::unix::net::UnixStream,
    count: usize,
    what: &str,
) -> io::Result<Vec<RawFd>> {
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
        // The far end died or never armed; every received descriptor in the
        // queue was closed by the kernel, so there is nothing to clean up.
        return Err(io::Error::other(format!(
            "the sandbox closed before handing over the {what}"
        )));
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
            "the sandbox handed over {} of {count} {what}",
            fds.len()
        )));
    }
    Ok(fds)
}

/// The control-message buffer space `count` descriptors need.
pub(crate) fn cmsg_space(count: usize) -> usize {
    unsafe { libc::CMSG_SPACE((count * size_of::<RawFd>()) as _) as usize }
}
