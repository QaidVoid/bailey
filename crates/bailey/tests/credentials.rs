//! Integration tests for the HTTP broker's credential bindings.
//!
//! The refusals run the whole `bailey` binary: a source that cannot be read
//! refuses the run before anything forks, and the test proves the target
//! never started. The live tests run bailey inside one fresh user, network
//! and mount namespace, where two intercepted hosts sit on stub upstreams
//! that record every header they were sent, and a secret rides the broker
//! to them alone.

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

fn unshare() -> Option<&'static str> {
    ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

fn isolation_ready() -> bool {
    if !bailey::backend::isolation::available() {
        return false;
    }
    let Some(unshare) = unshare() else {
        return false;
    };
    Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The secret every binding in these tests resolves to.
const SECRET: &str = "bailey-credential-v1";

/// The throwaway CA and leaf the stub upstreams serve, valid for
/// `cred.test` and `cred2.test`. The broker trusts the CA from the
/// sandbox's own `/etc/ssl/certs`; the target trusts the run's CA for the
/// termination leg.
const UPSTREAM_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUVv6aNpnsAc/I9UYwvdTA7MYOHuEwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMY3JlZC10ZXN0LWNhMCAXDTI2MTEyMTEyMjg1M1oYDzIxMjYx
MDI4MTIyODUzWjAXMRUwEwYDVQQDDAxjcmVkLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR7DsfpswmXNmF3/kosiakNiGlTNMJLXcyWZedp2to1ic4k
n2aK33orEcFniPX2Tu+Oniuiwhh1345FviUlQTFwo1MwUTAdBgNVHQ4EFgQUaM+3
bL43Egnxv2mzsUj8bUkl77owHwYDVR0jBBgwFoAUaM+3bL43Egnxv2mzsUj8bUkl
77owDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA5ipL4HD61rL8
ZnnoXl1r+w1OdC8EQXfFhly1xTLFe+kCICZO/leJf+kvfCmNJpWbtcJHf/uaCNgh
GDUhSK3bVdM1
-----END CERTIFICATE-----
";

const UPSTREAM_LEAF: &str = "-----BEGIN CERTIFICATE-----
MIIBwjCCAWigAwIBAgIUVUR1jtu8PziIKPW7YOHsC4MR7FswCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMY3JlZC10ZXN0LWNhMCAXDTI2MTEyMTEyMjg1M1oYDzIxMjYx
MDI4MTIyODUzWjAUMRIwEAYDVQQDDAljcmVkLnRlc3QwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQNNPqDgEK6tI+AC/ZzhKdv4ShR7U3JQZRrLV9OFGj57hyT9lN5
HzQPt+kvT04V/0VXuL5N9fbGcq//6hB8IJEBo4GSMIGPMCAGA1UdEQQZMBeCCWNy
ZWQudGVzdIIKY3JlZDIudGVzdDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUAaneE5rtyIeHLL4miV8q9ueBcoow
HwYDVR0jBBgwFoAUaM+3bL43Egnxv2mzsUj8bUkl77owCgYIKoZIzj0EAwIDSAAw
RQIhAP7/+jfg0iiLEBOWfXb2nKp5ad2FzBhDy6doTgaFAgmrAiAP2wg6Xjyev+RN
APzt8Na2wp7y0IBpDzD7MR7WOW7PfA==
-----END CERTIFICATE-----
";

const UPSTREAM_KEY: &str = "-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINEspzLOWC3KoyRXJiXnPRMEdYAMGI7Lyb6ss3hkKXg5oAoGCCqGSM49
AwEHoUQDQgAEDTT6g4BCurSPgAv2c4Snb+EoUe1NyUGUay1fThRo+e4ck/ZTeR80
D7fpL09OFf9FV7i+TfX2xnKv/+oQfCCRAQ==
-----END EC PRIVATE KEY-----
";

/// The policy for a run whose target is python in the sandbox: the usual
/// read and execute grants, the work directory for the probes, one `env`
/// pass that would carry the secret's variable if the credential did not
/// claim it, both hosts intercepted, and the bindings named by `sources`.
fn policy_toml(work: &Path, sources: &[(&str, &str, &str)], deny_private: bool) -> String {
    let work = work.display();
    let mut rules = String::new();
    for (host, _, _) in sources {
        rules.push_str(&format!(
            "\n[[http.allow]]\nhost = \"{host}\"\nport = 443\n"
        ));
    }
    if deny_private {
        rules.push_str("\n[[http.deny]]\nhost = \"cred.test\"\nport = 443\npath = \"/private\"\n");
    }
    let mut bindings = String::new();
    for (host, auth, source) in sources {
        bindings.push_str(&format!(
            "\n[[http.credential]]\nhost = \"{host}\"\nauth = \"{auth}\"\nsource = \"{source}\"\n"
        ));
    }
    format!(
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
         write = [\"{work}\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         \n\
         [network]\n\
         egress = \"allow\"\n\
         broker = \"builtin\"\n\
         \n\
         [env]\n\
         pass = [\"BAILEY_TEST_*\"]\n\
         \n\
         [http]\n\
         intercept = [\"cred.test\", \"cred2.test\"]\n\
         {rules}\n\
         {bindings}"
    )
}

/// The live run: one env-sourced and one fd-sourced credential, both
/// intercepted, both stubbed upstreams recording every header. The secret
/// reaches each upstream as the attached header and is found nowhere else:
/// not in the target's environment, not in the hook's, not in the broker's
/// `/proc` environ, not in `ps`, and descriptor 7 is gone for the hook and
/// the target alike.
#[test]
fn a_credential_rides_the_broker_and_lands_nowhere_else() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    if !isolation_ready() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "{}\n[hooks]\npre_launch = [\"/usr/bin/python3 {}/hook_probe.py {}/hook-fd7.txt\"]\n",
            policy_toml(
                &work,
                &[
                    ("cred.test", "bearer", "env:BAILEY_TEST_SECRET"),
                    ("cred2.test", "header:x-api-key", "fd:7"),
                ],
                true
            ),
            work.display(),
            work.display()
        ),
    )
    .unwrap();
    let secret_path = dir.path().join("secret.txt");
    fs::write(&secret_path, SECRET).unwrap();

    // The probe the hook runs: it tries descriptor 7 and names what it
    // sees of the secret's variable, into a file the test reads after.
    fs::write(
        work.join("hook_probe.py"),
        format!(
            "import os, sys\n\
             try:\n\
             \x20   os.lseek(7, 0, os.SEEK_SET)\n\
             \x20   data = os.read(7, 64)\n\
             \x20   seen = 'LEAKED:' + data.decode(errors='replace')\n\
             except OSError as e:\n\
             \x20   seen = 'EBADF' if e.errno == 9 else 'ERRNO:%d' % e.errno\n\
             env = os.environ.get('BAILEY_TEST_SECRET', 'ABSENT')\n\
             open(sys.argv[1], 'w').write(seen + ' SECRET=' + env + '\\n')\n"
        ),
    )
    .unwrap();

    // The target's probe: descriptor 7, the variable, and two requests
    // through the broker, the first carrying an Authorization of its own
    // for the broker to replace.
    let target_probe = r#"
import json, os, socket, ssl, subprocess, tempfile, time
from urllib.parse import urlparse

out = {}
try:
    os.lseek(7, 0, os.SEEK_SET)
    data = os.read(7, 64)
    out['fd7'] = 'LEAKED:' + data.decode(errors='replace')
except OSError as e:
    out['fd7'] = 'EBADF' if e.errno == 9 else 'ERRNO:%d' % e.errno
out['env_secret'] = os.environ.get('BAILEY_TEST_SECRET', 'ABSENT')

proxy = urlparse(os.environ['HTTPS_PROXY'])

def fetch(host, extra_headers=(), path='/ok'):
    sock = socket.create_connection((proxy.hostname, proxy.port), timeout=20)
    sock.settimeout(20)
    sock.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n' % (host, host)).encode())
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError('the proxy closed the CONNECT: ' + head.decode(errors='replace'))
        head += chunk
    status = head.split(b'\r\n', 1)[0].decode(errors='replace')
    if ' 200' not in status:
        return {'connect': status}
    ctx = ssl.create_default_context()
    tls = ctx.wrap_socket(sock, server_hostname=host)
    request = 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n' % (path, host)
    for name, value in extra_headers:
        request += '%s: %s\r\n' % (name, value)
    request += '\r\n'
    tls.sendall(request.encode())
    body = b''
    while True:
        try:
            chunk = tls.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        body += chunk
    tls.close()
    return {'status': body.split(b'\r\n', 1)[0].decode(errors='replace'),
            'payload': body.split(b'\r\n\r\n', 1)[-1].decode(errors='replace')}

def fetch_cleartext(host):
    # An absolute-form cleartext request to a host a credential is bound to:
    # the broker must refuse it with its reason.
    sock = socket.create_connection((proxy.hostname, proxy.port), timeout=20)
    sock.settimeout(20)
    sock.sendall(('GET http://%s:443/ok HTTP/1.1\r\nHost: %s:443\r\nConnection: close\r\n\r\n'
                  % (host, host)).encode())
    body = b''
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        body += chunk
    sock.close()
    return body.decode(errors='replace')

def inspect_presented(host):
    # What the termination actually presented, decoded without trust.
    try:
        sock = socket.create_connection((proxy.hostname, proxy.port), timeout=20)
        sock.settimeout(20)
        sock.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n' % (host, host)).encode())
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = sock.recv(4096)
            if not chunk:
                return 'proxy closed'
            head += chunk
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname=host)
        der = tls.getpeercert(binary_form=True)
        tls.close()
        import tempfile
        with tempfile.NamedTemporaryFile('wb', suffix='.der', delete=False) as tmp:
            tmp.write(der)
        decoded = subprocess.run(['openssl', 'x509', '-in', tmp.name, '-noout',
                                  '-subject', '-issuer'], capture_output=True)
        return decoded.stdout.decode(errors='replace')
    except Exception as e:
        return 'inspect failed: ' + repr(e)

try:
    out['cred'] = fetch('cred.test', [('Authorization', 'attacker-value')])
except Exception as e:
    out['cred'] = {'error': repr(e)}
    out['presented'] = inspect_presented('cred.test')
try:
    out['cred2'] = fetch('cred2.test')
except Exception as e:
    out['cred2'] = {'error': repr(e)}
try:
    out['private'] = fetch('cred.test', path='/private')
except Exception as e:
    out['private'] = {'error': repr(e)}
try:
    out['cleartext'] = fetch_cleartext('cred.test')
except Exception as e:
    out['cleartext'] = repr(e)
print('CREDREPORT ' + json.dumps(out), flush=True)
# Hold the run open, so the orchestrator has a comfortable window to find
# the broker in /proc and read what it may.
time.sleep(15)
"#;
    fs::write(work.join("target_probe.py"), target_probe).unwrap();

    let script = r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading, time
import ctypes
import http.server

bailey_path, config_path, work, ca_pem, leaf_pem, key_pem, secret_path = sys.argv[1:8]
SECRET = open(secret_path).read().strip()
records = {}
lock = threading.Lock()

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 cred.test\n10.0.0.8 cred2.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_pem) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

# Loopback comes up with both stub addresses on it.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.8')))
sock.close()

class Served(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host', '').split(':')[0]
        with lock:
            records.setdefault(host, []).append({
                'path': self.path,
                'authorization': self.headers.get('Authorization'),
                'x-api-key': self.headers.get('x-api-key'),
            })
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '12')
        self.end_headers()
        self.wfile.write(b'upstream-ok\n')
    def log_message(self, *rest):
        pass

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_pem, key_pem)
servers = []
for address in ('10.0.0.7', '10.0.0.8'):
    server = http.server.ThreadingHTTPServer((address, 443), Served)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)

# The descriptor source: a secret regular file on descriptor 7, with no
# close-on-exec flag. Descriptor 7 must be free; the dup happens before
# bailey is spawned, and pass_fds carries it across.
try:
    fcntl.fcntl(7, fcntl.F_GETFD)
    print(json.dumps({'error': 'descriptor 7 is not free'}))
    sys.exit(3)
except OSError:
    pass
source = os.open(secret_path, os.O_RDONLY)
os.dup2(source, 7)
os.close(source)

env = dict(os.environ)
env['BAILEY_TEST_SECRET'] = SECRET
run = subprocess.Popen(
    [bailey_path, 'run', '-c', config_path, '/usr/bin/python3', work + '/target_probe.py'],
    cwd=work, pass_fds=(7,), env=env,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def find_broker(timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open(f'/proc/{pid}/comm') as comm:
                    if comm.read().strip() == 'bailey-broker':
                        return int(pid)
            except OSError:
                continue
        time.sleep(0.2)
    return None

report = {}
marks = {'popen': time.time()}
broker_pid = find_broker()
marks['found_or_gave_up'] = time.time()
report['host_bundles'] = {}
try:
    for path in sorted(__import__('glob').glob('/tmp/.bailey-ca.*/ca-bundle.pem')):
        import hashlib
        body = open(path, 'rb').read()
        report['host_bundles'][path] = f'{len(body)}:{hashlib.sha256(body).hexdigest()[:16]}'
except Exception as e:
    report['host_bundles'] = {'error': repr(e)}
if broker_pid is None:
    try:
        stdout, stderr = run.communicate(timeout=10)
        print(json.dumps({'error': 'no broker process appeared',
                          'exit': run.returncode,
                          'stdout': stdout.decode(errors='replace')[:4000],
                          'stderr': stderr.decode(errors='replace')[:4000]}))
    except subprocess.TimeoutExpired:
        run.kill()
        run.wait()
        print(json.dumps({'error': 'no broker process appeared and the run hung'}))
    sys.exit(3)
try:
    with open(f'/proc/{broker_pid}/environ', 'rb') as environ:
        contents = environ.read()
    report['broker_environ'] = 'HAS_SECRET' if SECRET.encode() in contents else 'READABLE_CLEAN'
except OSError as e:
    report['broker_environ'] = f'UNREADABLE:{e.errno}'
ps = '/usr/bin/ps'
if os.path.exists(ps):
    listing = subprocess.run([ps, 'ewww', '-p', str(broker_pid)],
                             capture_output=True, timeout=10)
    report['ps'] = 'HAS_SECRET' if SECRET.encode() in listing.stdout else 'CLEAN'
else:
    report['ps'] = 'ABSENT'

try:
    stdout, stderr = run.communicate(timeout=180)
except subprocess.TimeoutExpired:
    run.kill()
    run.wait()
    print(json.dumps({'error': 'the run hung'}))
    sys.exit(3)
marks['communicated'] = time.time()
report['exit'] = run.returncode
report['marks'] = {name: round(when - marks['popen'], 2) for name, when in marks.items()}
report['stderr'] = stderr.decode(errors='replace')
report_line = None
for line in stdout.decode(errors='replace').splitlines():
    if line.startswith('CREDREPORT '):
        report_line = line[len('CREDREPORT '):]
report['target'] = json.loads(report_line) if report_line else None
with lock:
    report['records'] = records
for server in servers:
    server.shutdown()
print(json.dumps(report), flush=True)
"#
    .to_string();
    let script_path = dir.path().join("sandbox.py");
    fs::write(&script_path, script).unwrap();
    fs::write(dir.path().join("ca.pem"), UPSTREAM_CA).unwrap();
    fs::write(dir.path().join("leaf.pem"), UPSTREAM_LEAF).unwrap();
    fs::write(dir.path().join("leaf.key"), UPSTREAM_KEY).unwrap();

    let output = Command::new(unshare().unwrap())
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(bailey())
        .arg(&config)
        .arg(&work)
        .arg(dir.path().join("ca.pem"))
        .arg(dir.path().join("leaf.pem"))
        .arg(dir.path().join("leaf.key"))
        .arg(&secret_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}; report: {stdout}");
    }
    assert_eq!(report["exit"], 0, "the run failed: {:?}", report["stderr"]);
    let stderr = report["stderr"].as_str().unwrap();
    assert!(
        stderr.contains("env pass would forward BAILEY_TEST_SECRET")
            && stderr.contains("cred.test"),
        "the pass that would have carried the secret must be noted: {stderr}"
    );

    // The attached headers reached each upstream, and the target's own
    // Authorization did not survive it: the bearer credential on the first
    // host, the named-header credential on the second.
    let attached_bearer = serde_json::json!({
        "path": "/ok",
        "authorization": format!("Bearer {SECRET}"),
        "x-api-key": serde_json::Value::Null,
    });
    let attached_header = serde_json::json!({
        "path": "/ok",
        "authorization": serde_json::Value::Null,
        "x-api-key": SECRET,
    });
    assert_eq!(report["records"]["cred.test"], serde_json::json!([attached_bearer]), "records: {}", stdout);
    assert_eq!(report["records"]["cred2.test"], serde_json::json!([attached_header]), "{}", stdout);
    let target = &report["target"];
    assert!(
        target["cred"].get("error").is_none() && target["cred2"].get("error").is_none(),
        "the target's requests failed: {}",
        serde_json::to_string_pretty(target).unwrap()
    );

    // Descriptor 7 is gone for the target, and its environment holds no
    // secret; both requests were answered with the upstream's page.
    let target = &report["target"];
    assert_eq!(target["fd7"], "EBADF", "{}", stdout);
    assert_eq!(target["env_secret"], "ABSENT", "{}", stdout);
    assert!(
        target["cred"]["status"].as_str().unwrap().contains("200"),
        "{}", stdout
    );
    assert_eq!(target["cred"]["payload"], "upstream-ok\n", "{}", stdout);
    assert!(
        target["cred2"]["status"].as_str().unwrap().contains("200"),
        "{}", stdout
    );

    // The denied path never reached the upstream and never carried the
    // credential: the broker answers, the stub records nothing more, and
    // the answer names the deny rule.
    assert!(
        target["private"]["status"].as_str().unwrap_or("").contains("403"),
        "the denied path must be refused: {}",
        serde_json::to_string_pretty(target).unwrap()
    );
    assert!(
        target["private"]["payload"]
            .as_str()
            .unwrap_or("")
            .contains("denied by deny rule"),
        "{}", stdout
    );

    // Cleartext to a bound host is refused with its reason, and again no
    // upstream connection happened.
    let cleartext = target["cleartext"].as_str().unwrap_or("");
    assert!(
        cleartext.contains("403") && cleartext.contains("served over TLS only"),
        "cleartext to a bound host must be refused with its reason: {cleartext}"
    );

    // The hook saw the same: no descriptor, no variable.
    let hook = fs::read_to_string(work.join("hook-fd7.txt")).unwrap();
    assert!(
        hook.starts_with("EBADF SECRET=ABSENT"),
        "the hook must find neither descriptor 7 nor the variable: {hook}"
    );

    // The broker's own environment, however it was asked for, holds no
    // secret.
    let environ = report["broker_environ"].as_str().unwrap();
    assert!(environ != "HAS_SECRET", "{stdout}");
    assert!(report["ps"] != "HAS_SECRET", "{stdout}");
}

/// Run bailey with a target that would leave a marker, and return the
/// output for the assertions. The working directory is the scratch dir, so
/// no config of the repository's own is discovered.
fn refused_run(config: &Path, work: &Path) -> std::process::Output {
    let marker = work.join("target-ran");
    Command::new(bailey())
        .current_dir(work)
        .args(["run", "-c"])
        .arg(config)
        .args(["/bin/sh", "-c"])
        .arg(format!("touch {}", marker.display()))
        .output()
        .unwrap()
}

fn assert_refused(output: &std::process::Output, work: &Path, expected: &[&str]) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the run must be refused: {stderr}"
    );
    for fragment in expected {
        assert!(
            stderr.contains(fragment),
            "the refusal must name `{fragment}`: {stderr}"
        );
    }
    assert!(
        !work.join("target-ran").exists(),
        "the target must never start on a refused credential: {stderr}"
    );
}

/// A source naming an unset variable refuses the run, and the refusal
/// names the binding.
#[test]
fn a_missing_env_source_refuses_the_run_and_names_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(dir.path(), &[("cred.test", "bearer", "env:BAILEY_TEST_ABSENT")], false),
    )
    .unwrap();
    assert_refused(
        &refused_run(&config, dir.path()),
        dir.path(),
        &["cred.test", "BAILEY_TEST_ABSENT", "not set"],
    );
}

/// A file holding nothing but a line break reads as empty, and the refusal
/// names the binding.
#[test]
fn an_empty_credential_refuses_the_run_and_names_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("empty.txt");
    fs::write(&secret, "\n").unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(
            dir.path(),
            &[("cred.test", "bearer", &format!("file:{}", secret.display()))],
            false,
        ),
    )
    .unwrap();
    assert_refused(
        &refused_run(&config, dir.path()),
        dir.path(),
        &["cred.test", "empty value"],
    );
}

/// A value with a line break in it cannot ride a header, and the refusal
/// names the binding.
#[test]
fn a_multiline_credential_refuses_the_run_and_names_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("multi.txt");
    fs::write(&secret, "first\r\nsecond").unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(
            dir.path(),
            &[("cred.test", "bearer", &format!("file:{}", secret.display()))],
            false,
        ),
    )
    .unwrap();
    assert_refused(
        &refused_run(&config, dir.path()),
        dir.path(),
        &["cred.test", "line break"],
    );
}

/// A descriptor among the target's own streams is refused as a source.
#[test]
fn a_standard_stream_is_refused_as_a_descriptor_source() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(dir.path(), &[("cred.test", "bearer", "fd:1")], false),
    )
    .unwrap();
    assert_refused(
        &refused_run(&config, dir.path()),
        dir.path(),
        &["cred.test", "descriptor 1", "own streams"],
    );
}

/// One descriptor cannot carry two bindings: the first resolves, the
/// second refuses the run. The descriptor is placed on 9 inside the forked
/// child, so no descriptor of the test process itself is touched: this
/// binary runs every test as a thread of one process, and a `dup2` in the
/// parent would stomp another test's pipes.
#[test]
fn a_descriptor_named_twice_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, SECRET).unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(dir.path(), &[("cred.test", "bearer", "fd:9"), ("cred2.test", "bearer", "fd:9")], false),
    )
    .unwrap();
    let path = std::ffi::CString::new(secret.as_os_str().as_encoded_bytes()).unwrap();
    let mut run = Command::new(bailey());
    run.current_dir(dir.path())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("touch {}", dir.path().join("target-ran").display()));
    // Safety: runs in the forked child before exec, where the open is
    // async-signal-safe, and no descriptor of the parent is disturbed.
    unsafe {
        run.pre_exec(move || {
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if fd != 9 && libc::dup2(fd, 9) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if fd != 9 {
                libc::close(fd);
            }
            Ok(())
        });
    }
    let output = run.output().unwrap();
    assert_refused(
        &output,
        dir.path(),
        &["cred2.test", "descriptor 9", "another binding"],
    );
}

/// A descriptor that is not open refuses the run.
#[test]
fn a_closed_descriptor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        policy_toml(dir.path(), &[("cred.test", "bearer", "fd:99")], false),
    )
    .unwrap();
    assert_refused(
        &refused_run(&config, dir.path()),
        dir.path(),
        &["cred.test", "descriptor 99", "not open"],
    );
}

/// A credential that names `header:` with a framing or hop-by-hop name is
/// a config error: the broker strips those headers itself, so the
/// attachment would silently vanish.
#[test]
fn a_credential_on_a_stripped_header_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, policy_toml(dir.path(), &[], false)).unwrap();
    let with_header = format!(
        "{}\n[[http.credential]]\nhost = \"cred.test\"\nauth = \"header:Transfer-Encoding\"\nsource = \"env:BAILEY_TEST_ABSENT\"\n",
        fs::read_to_string(&config).unwrap()
    );
    fs::write(&config, with_header).unwrap();
    let output = refused_run(&config, dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the config must be refused: {stderr}"
    );
    assert!(
        stderr.contains("the broker writes or strips itself"),
        "the refusal must name the stripped header: {stderr}"
    );
}
