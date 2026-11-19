//! Helpers shared by the integration test binaries.

use std::fs;
use std::path::{Path, PathBuf};

/// A probe that asks the kernel for a fresh user and network namespace
/// through clone3, clone, and unshare, and reports what happened on stdout.
/// Each route that creates a child prints the child's effective capabilities
/// so a caller can tell a real namespace creation from a refusal.
pub fn write_namespace_probe(dir: &Path) -> PathBuf {
    let probe = dir.join("probe.py");
    fs::write(
        &probe,
        r#"
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
flags = 0x10000000 | 0x40000000
SYS_CLONE3 = 435
SYS_CLONE = 56 if platform.machine() == 'x86_64' else 220

def capseff():
    with open('/proc/self/status') as status:
        for line in status:
            if line.startswith('CapEff'):
                return line.split()[1].strip()
    return '?'

buf = (ctypes.c_uint64 * 8)(flags, 0, 0, 0, 17, 0, 0, 0)
pid = libc.syscall(SYS_CLONE3, buf, 64)
if pid == 0:
    print('clone3 child CapEff', capseff(), flush=True)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
    print('clone3 child-created', flush=True)
else:
    print('clone3 refused', ctypes.get_errno(), flush=True)

pid = libc.syscall(SYS_CLONE, flags, 0, 0, 0, 0)
if pid == 0:
    print('clone child CapEff', capseff(), flush=True)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
    print('clone child-created', flush=True)
else:
    print('clone refused', ctypes.get_errno(), flush=True)

if libc.unshare(flags) == 0:
    print('unshare succeeded CapEff', capseff(), flush=True)
else:
    print('unshare refused', ctypes.get_errno(), flush=True)
"#,
    )
    .unwrap();
    probe
}

/// Assert that every route a probe took to a fresh user namespace was
/// refused, with the errno the kernel hands back for a real refusal: EPERM
/// from the seccomp filter, ENOSYS from the clone3 rule, or ENOSPC from the
/// guard's limit. No route may leave a child holding capabilities.
pub fn assert_every_namespace_route_refused(layout: &str, stdout: &str) {
    for route in ["clone3", "clone", "unshare"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(route))
            .unwrap_or_else(|| panic!("{layout}: no {route} probe output: {stdout}"));
        let errno: i32 = line
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| panic!("{layout}: {route} probe did not report an errno: {line}"));
        assert!(
            [1, 28, 38].contains(&errno),
            "{layout}: {route} must be refused with EPERM, ENOSPC, or ENOSYS: {line}"
        );
    }
    assert!(
        !stdout.contains("CapEff") && !stdout.contains("child-created"),
        "{layout}: the target must not gain capabilities in a new user namespace: {stdout}"
    );
}
