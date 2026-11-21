import ipaddress
import os
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def resolve_executable(bin_spec: str, fallback_dir: Optional[Path] = None) -> Optional[str]:
    """Safely resolves a binary name or explicit absolute path without traversal."""
    if not bin_spec or ".." in bin_spec:
        return None
    candidate = Path(bin_spec)
    if candidate.is_absolute():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    if "/" in bin_spec or "\\" in bin_spec:
        return None
    found = shutil.which(bin_spec)
    if not found and fallback_dir is not None:
        local = fallback_dir / bin_spec
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
    return found


def check_os_sandbox_support(
    bwrap_bin: str = "bwrap",
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Independently verifies that Linux OS namespace sandboxing via Bubblewrap (bwrap)
    is functional without privilege escalation. Fails closed when unavailable.
    """
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return False, None, "OpenCode OS namespace sandbox (bwrap) requires POSIX Linux."

    if hasattr(os, "geteuid") and hasattr(os, "getuid"):
        if os.geteuid() != os.getuid():
            return False, None, "Privilege escalation mismatch detected (euid != uid); refusing sandbox."

    resolved_bwrap = resolve_executable(bwrap_bin)
    if not resolved_bwrap:
        return False, None, "Bubblewrap (bwrap) binary is not installed or not executable."

    if not hasattr(os, "killpg") or not hasattr(os, "getpgid"):
        return False, None, "Process group isolation (os.killpg/getpgid) is unavailable."

    try:
        import resource  # noqa: F401
    except ImportError:
        return False, None, "POSIX resource limit controls are unavailable."

    probe_cmd = [
        resolved_bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--clearenv",
        "/bin/true",
    ]
    try:
        probe = subprocess.run(
            probe_cmd,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
        if probe.returncode != 0:
            err = (probe.stderr or probe.stdout or "").strip()[:160]
            return False, None, f"Bubblewrap namespace isolation probe failed ({err or probe.returncode})."
    except Exception as exc:
        return False, None, f"Bubblewrap namespace probe error: {type(exc).__name__}"

    return True, resolved_bwrap, None


def parse_approved_provider_target(url: str) -> Tuple[str, int]:
    """Validates and extracts exact (host, port) from an explicitly approved provider base URL."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in ("https", "http"):
        raise ValueError("Approved provider URL must use http or https scheme.")
    if not parsed.hostname:
        raise ValueError("Approved provider URL missing valid hostname.")
    host = parsed.hostname.lower()
    if host in ("*", "0.0.0.0", "169.254.169.254", "metadata.google.internal"):
        raise ValueError(f"Disallowed provider target host '{host}'.")
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_link_local or ip_obj.is_multicast:
            raise ValueError(f"Disallowed link-local/multicast target IP '{host}'.")
    except ValueError as exc:
        if "Disallowed" in str(exc):
            raise
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port <= 0 or port > 65535:
        raise ValueError("Approved provider URL port out of bounds.")
    return host, port


def _relay_duplex(sock_a: socket.socket, sock_b: socket.socket) -> None:
    try:
        sockets = [sock_a, sock_b]
        while True:
            readable, _, _ = select.select(sockets, [], [], 30.0)
            if not readable:
                break
            for s in readable:
                data = s.recv(8192)
                if not data:
                    return
                peer = sock_b if s is sock_a else sock_a
                peer.sendall(data)
    except OSError:
        pass
    finally:
        for s in (sock_a, sock_b):
            try:
                s.close()
            except OSError:
                pass


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class ApprovedProviderProxy:
    """
    Host-side HTTP/CONNECT Unix-socket egress filter for network-isolated (--unshare-net)
    Bubblewrap sandboxes. Allows connections strictly to ONE explicitly approved (host, port).
    """

    def __init__(self, socket_path: Path, allowed_host: str, allowed_port: int) -> None:
        self.socket_path = socket_path
        self.allowed_host = allowed_host.lower()
        self.allowed_port = int(allowed_port)
        self._server: Optional[_ThreadingUnixServer] = None
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "ApprovedProviderProxy":
        if self.socket_path.exists():
            self.socket_path.unlink()

        allowed_host = self.allowed_host
        allowed_port = self.allowed_port

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                client: socket.socket = self.request
                upstream: Optional[socket.socket] = None
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf and len(buf) < 16384:
                        chunk = client.recv(4096)
                        if not chunk:
                            return
                        buf += chunk
                    header_end = buf.find(b"\r\n\r\n")
                    if header_end < 0:
                        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        return
                    head = buf[:header_end].decode("latin-1", errors="replace")
                    rest = buf[header_end + 4 :]
                    first_line = head.splitlines()[0] if head.splitlines() else ""
                    parts = first_line.split()
                    if len(parts) < 2:
                        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        return

                    method, target = parts[0].upper(), parts[1]
                    if method == "CONNECT":
                        t_host, _, t_port_str = target.partition(":")
                        t_port = int(t_port_str) if t_port_str.isdigit() else 443
                        if t_host.lower() != allowed_host or t_port != allowed_port:
                            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nEgress host denied by policy.")
                            return
                        upstream = socket.create_connection((allowed_host, allowed_port), timeout=10.0)
                        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        if rest:
                            upstream.sendall(rest)
                        _relay_duplex(client, upstream)
                    else:
                        parsed = urlparse(target)
                        t_host = (parsed.hostname or "").lower()
                        t_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                        if t_host != allowed_host or t_port != allowed_port:
                            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nEgress host denied by policy.")
                            return
                        upstream = socket.create_connection((allowed_host, allowed_port), timeout=10.0)
                        upstream.sendall(buf)
                        _relay_duplex(client, upstream)
                except Exception:
                    try:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    except OSError:
                        pass
                finally:
                    if upstream is not None:
                        try:
                            upstream.close()
                        except OSError:
                            pass

        self._server = _ThreadingUnixServer(str(self.socket_path), Handler)
        os.chmod(self.socket_path, 0o600)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.5)


_SANDBOX_LOOPBACK_BRIDGE = """
import os, select, socket, subprocess, sys, threading
sock_path = "/sandbox/egress.sock"
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(32)
port = srv.getsockname()[1]

def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 30.0)
            if not r:
                break
            for x in r:
                d = x.recv(8192)
                if not d:
                    return
                (b if x is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except OSError: pass

def accept_loop():
    while True:
        try:
            c, _ = srv.accept()
            u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            u.connect(sock_path)
            threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        except OSError:
            break

threading.Thread(target=accept_loop, daemon=True).start()
env = dict(os.environ)
proxy_url = f"http://127.0.0.1:{port}"
env["HTTPS_PROXY"] = proxy_url
env["HTTP_PROXY"] = proxy_url
env["ALL_PROXY"] = proxy_url
env["NO_PROXY"] = ""
proc = subprocess.run(sys.argv[1:], env=env)
srv.close()
sys.exit(proc.returncode)
""".strip()


def build_bwrap_command(
    resolved_bwrap: str,
    resolved_opencode: str,
    tmpdir: Path,
    sandbox_env: Dict[str, str],
    inner_args: List[str],
    max_tmpfs_bytes: int = 16777216,
    allow_network: bool = False,
    egress_socket_path: Optional[Path] = None,
) -> List[str]:
    """
    Constructs a strict Bubblewrap CLI invocation array confining execution to an isolated
    read-only/ephemeral namespace without exposing the host filesystem or Malbox repo.
    """
    tmpfs_size = str(max(4194304, int(max_tmpfs_bytes)))
    cmd: List[str] = [
        resolved_bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind-try",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf",
        "--ro-bind-try",
        "/etc/ld.so.conf.d",
        "/etc/ld.so.conf.d",
        "--ro-bind-try",
        "/etc/ssl",
        "/etc/ssl",
        "--ro-bind-try",
        "/etc/ca-certificates",
        "/etc/ca-certificates",
        "--ro-bind-try",
        "/etc/pki",
        "/etc/pki",
        "--ro-bind-try",
        "/etc/nsswitch.conf",
        "/etc/nsswitch.conf",
        "--ro-bind-try",
        "/etc/localtime",
        "/etc/localtime",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/sandbox",
        "--size",
        tmpfs_size,
        "--tmpfs",
        "/tmp",
        "--size",
        tmpfs_size,
        "--tmpfs",
        "/sandbox/.xdg",
        "--ro-bind",
        str(tmpdir / "evidence_bundle.json"),
        "/sandbox/evidence_bundle.json",
        "--ro-bind",
        str(tmpdir / "opencode.json"),
        "/sandbox/opencode.json",
        "--ro-bind",
        str(tmpdir / ".opencode"),
        "/sandbox/.opencode",
        "--ro-bind",
        resolved_opencode,
        "/opt/opencode/opencode",
        "--chdir",
        "/sandbox",
        "--clearenv",
    ]

    for k, v in sorted(sandbox_env.items()):
        cmd.extend(["--setenv", k, v])

    if allow_network and egress_socket_path is not None:
        cmd.extend(["--bind", str(egress_socket_path), "/sandbox/egress.sock"])
        cmd.append("--")
        py_bin = "/usr/bin/python3" if Path("/usr/bin/python3").is_file() else "/bin/python3"
        cmd.extend([py_bin, "-c", _SANDBOX_LOOPBACK_BRIDGE])
    else:
        cmd.append("--")

    cmd.extend(["/opt/opencode/opencode", *inner_args])
    return cmd
