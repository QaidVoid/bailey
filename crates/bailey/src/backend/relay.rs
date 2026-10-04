//! Host-side relays that carry named UNIX sockets into the sandbox.
//!
//! A desktop service keeps its socket in the session runtime directory beside
//! sockets that must never cross: ssh-agent, gpg-agent, PipeWire. Granting the
//! directory hands over all of them, and Landlock on this kernel cannot
//! separate one pathname socket from another. A relay separates them in
//! userspace instead: bailey listens on a socket of its own, the sandbox sees
//! that socket at the service's usual path, and every connection is carried to
//! the real socket by bailey, which is on the host and holds no policy. The
//! directory itself is never granted, so the sockets beside the service stay
//! out of reach.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;

/// The prefix of the per-run directories holding staged relay sockets.
const PREFIX: &str = ".bailey-sock.";

/// One relayed socket: listened for on the host, presented to the target at
/// its usual path.
pub(crate) struct Relay {
    /// Where the target sees the socket.
    pub(crate) at: PathBuf,
    /// The host path of the listening socket, which is what gets bound into
    /// the sandbox.
    pub(crate) listener_path: PathBuf,
    listener: UnixListener,
}

impl Relay {
    /// Serve connections until the process ends.
    ///
    /// Each accepted connection is carried to the host socket in its own
    /// thread, connected lazily: a client that opens and closes without
    /// speaking never touches the real service. The threads are detached;
    /// they end when their sockets do, and the sockets end with the run.
    pub(crate) fn serve(&self, host: &Path) {
        let listener = match self.listener.try_clone() {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!(
                    "bailey: warning: the relay for {} stopped: {err}",
                    self.at.display()
                );
                return;
            }
        };
        let host = host.to_path_buf();
        thread::spawn(move || {
            while let Ok((client, _addr)) = listener.accept() {
                let host = host.clone();
                thread::spawn(move || forward(client, host));
            }
        });
    }
}

/// Carry one connection between the sandbox side and the host socket.
fn forward(client: UnixStream, host: PathBuf) {
    let Ok(service) = UnixStream::connect(&host) else {
        // The service is down or its socket moved. Closing the client is the
        // honest answer; a desktop program retries.
        return;
    };
    let Ok(mut client_out) = client.try_clone() else {
        return;
    };
    let Ok(mut service_out) = service.try_clone() else {
        return;
    };
    // Each direction propagates the end it sees: when the client stops
    // writing, the service learns the request is complete, and when the
    // service stops answering, the client's read reaches an end. Without the
    // shutdown, the relay's own held descriptors would keep both sides
    // waiting forever.
    let up = thread::spawn(move || {
        let copied = io::copy(&mut client_out, &mut service_out);
        let _ = service_out.shutdown(std::net::Shutdown::Write);
        copied
    });
    let down = thread::spawn(move || {
        let mut service = service;
        let mut client = client;
        let copied = io::copy(&mut service, &mut client);
        let _ = client.shutdown(std::net::Shutdown::Write);
        copied
    });
    let _ = up.join();
    let _ = down.join();
}

/// The relays of one run, torn down when the guard drops.
pub(crate) struct RelayGuard {
    dir: PathBuf,
    relays: Vec<Relay>,
}

impl RelayGuard {
    /// The relays, in the order they were created.
    pub(crate) fn relays(&self) -> &[Relay] {
        &self.relays
    }
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        // Dropping the listeners closes them; a socket file left behind in a
        // directory of our own is removed with the directory.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Listen for a relay at every path in `at_paths`, staging the sockets under
/// `dir`, in order.
pub(crate) fn listen_all(at_paths: &[PathBuf], dir: &Path) -> io::Result<RelayGuard> {
    std::fs::create_dir_all(dir)?;
    let mut relays = Vec::new();
    for (index, at) in at_paths.iter().enumerate() {
        let listener_path = dir.join(index.to_string());
        let listener = UnixListener::bind(&listener_path)?;
        relays.push(Relay {
            at: at.clone(),
            listener_path,
            listener,
        });
    }
    Ok(RelayGuard {
        dir: dir.to_path_buf(),
        relays,
    })
}

/// The per-run directory holding this run's staged relay sockets.
pub(crate) fn run_dir() -> PathBuf {
    PathBuf::from(format!("/tmp/{PREFIX}{}", std::process::id()))
}

/// Remove the run directory of runs that are over.
///
/// The staged sockets are the only contents, so an empty-directory removal
/// cannot catch anything else. A leftover from a crashed run holds a socket
/// no one listens on, which connecting to reports as refused.
pub(crate) fn sweep_stale() {
    let Ok(entries) = std::fs::read_dir("/tmp") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(owner) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|owner| owner.parse::<u32>().ok())
        else {
            continue;
        };
        if Path::new("/proc").join(owner.to_string()).exists() {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A service listening on the host, a relay in front of it, and a client
    /// that only knows the relay: the bytes must make the round trip. This is
    /// the whole protocol; everything else is placement.
    #[test]
    fn a_client_through_the_relay_reaches_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let service_path = dir.path().join("real.sock");
        let service = UnixListener::bind(&service_path).unwrap();

        // The service echoes one line, the way a display or bus answers.
        thread::spawn(move || {
            let (mut conn, _) = service.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            conn.write_all(&buf[..n]).unwrap();
        });

        let staged = dir.path().join("staged");
        let guard = listen_all(&[PathBuf::from("/run/user/1000/wayland-0")], &staged).unwrap();
        assert_eq!(guard.relays().len(), 1);
        guard.relays()[0].serve(&service_path);

        let mut client = UnixStream::connect(&guard.relays()[0].listener_path).unwrap();
        client.write_all(b"ping").unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"ping");
    }

    /// A client that connects to the relay when the service is down is
    /// dropped, not hung: the relay never blocks the sandbox on the host.
    #[test]
    fn a_relay_with_no_service_closes_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let guard = listen_all(&[PathBuf::from("/run/user/1000/bus")], &staged).unwrap();
        guard.relays()[0].serve(&dir.path().join("missing.sock"));

        let mut client = UnixStream::connect(&guard.relays()[0].listener_path).unwrap();
        // The relay may close before this write lands, so the write itself
        // can be reset. What the contract rules out is a reply or a hang: the
        // read ends, one way or the other, and carries nothing.
        let _ = client.write_all(b"hello");
        let mut buf = Vec::new();
        let ended = client.read_to_end(&mut buf);
        assert!(
            ended
                .map(|n| n == 0)
                .unwrap_or_else(|err| err.kind() == io::ErrorKind::ConnectionReset),
            "the relay must not answer for a missing service"
        );
    }

    /// Dropping the guard removes the staged sockets, so a run leaves nothing
    /// behind in /tmp.
    #[test]
    fn a_guard_removes_its_staged_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let guard = listen_all(&[PathBuf::from("/run/user/1000/pulse")], &staged).unwrap();
        let socket = &guard.relays()[0].listener_path.to_path_buf();
        assert!(socket.exists());
        drop(guard);
        assert!(!socket.exists(), "the staged socket must not outlive the run");
    }
}
