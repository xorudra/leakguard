#!/usr/bin/env python3
"""Local CONNECT relay -> upstream authenticated proxy (from env).
Forwards CONNECT using Python sockets (which the upstream accepts), so
Chromium can use http://127.0.0.1:8899 without credentials.

LOCAL-ONLY (Phase 178 decision, docs/DOC_REVIEW.md): a development
tool for proxy-locked networks like this project's dev VM. The
LeakGuard server never imports or executes it — app.py and every
server package have zero references to it (grep audit,
2026-10-08), and it imports no project code. Its live users are
the local browser probe (via LEAKGUARD_BROWSER_PROXY) and the
repo's live-site check tools (tools/mobile_viewport_check.py,
tools/a11y_check.py), which start it when it is not running.

RELAY GUARDS (security audit 2026-10-16,
proxy_relay.unauthenticated-connect-confused-deputy): this process
holds WORKING upstream proxy credentials, so an unauthenticated
open relay on loopback would lend them to any local process (or
anything that can reach the port through a forward) for arbitrary
destinations. The relay therefore refuses by default:
* targets: port 443 only, and the host must be allowlisted —
  LEAKGUARD_RELAY_HOSTS (comma-separated; an entry starting with
  '.' matches that suffix) defaulting to the two origins the
  check tools exist for. Checking another origin means naming it
  in the env when starting the relay — deliberately.
* clients: when LEAKGUARD_RELAY_TOKEN is set, CONNECT must carry
  Proxy-Authorization for user 'leakguard' with the token as the
  password (the check tools pass it from the same env var).
* lifetime: the accept loop exits after
  LEAKGUARD_RELAY_MAX_MINUTES (default 120); idle tunnels
  already die on the pipe timeout below.
"""
import base64
import os
import select
import socket
import threading
import time
import urllib.parse

UP = urllib.parse.urlparse(os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))
UP_HOST = UP.hostname
UP_PORT = UP.port or 3128
AUTH = base64.b64encode(f"{urllib.parse.unquote(UP.username or '')}:{urllib.parse.unquote(UP.password or '')}".encode()).decode()

_DEFAULT_HOSTS = "leakguard-staging.onrender.com,152-67-23-189.sslip.io"
ALLOWED_HOSTS = [h.strip().lower() for h in
                 os.environ.get("LEAKGUARD_RELAY_HOSTS",
                                _DEFAULT_HOSTS).split(",") if h.strip()]
RELAY_TOKEN = os.environ.get("LEAKGUARD_RELAY_TOKEN") or ""
MAX_LIFETIME_SECONDS = int(
    os.environ.get("LEAKGUARD_RELAY_MAX_MINUTES", "120")) * 60


def host_allowed(host):
    host = (host or "").lower().rstrip(".")
    for entry in ALLOWED_HOSTS:
        if entry.startswith("."):
            if host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def client_authorized(headers):
    """When no token is configured the relay keeps its historic
    loopback-only posture (plus the target allowlist above);
    with a token, the CONNECT must prove it."""
    if not RELAY_TOKEN:
        return True
    expected = "Basic " + base64.b64encode(
        ("leakguard:" + RELAY_TOKEN).encode()).decode()
    return headers.get("proxy-authorization", "") == expected


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return infos[0][4][0]
    except Exception:
        return host


def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a], [], [], 60)
            if not r:
                break
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


def handle(client):
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                client.close(); return
            buf += chunk
        head = buf.split(b"\r\n\r\n")[0].decode("latin-1")
        lines = head.split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        if method.upper() != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Only CONNECT\r\n\r\n"); client.close(); return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if not client_authorized(headers):
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            client.close(); return
        host, _, port = target.rpartition(":")
        if port != "443" or not host_allowed(host):
            client.sendall(b"HTTP/1.1 403 Relay target refused\r\n\r\n")
            client.close(); return
        upstream = socket.create_connection((resolve(UP_HOST), UP_PORT), timeout=20)
        req = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
               f"Proxy-Authorization: Basic {AUTH}\r\nProxy-Connection: keep-alive\r\n\r\n")
        upstream.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = upstream.recv(4096)
            if not chunk:
                client.close(); upstream.close(); return
            resp += chunk
        status_line = resp.split(b"\r\n")[0].decode("latin-1")
        if " 200" not in status_line:
            client.sendall(f"HTTP/1.1 502 Upstream said: {status_line}\r\n\r\n".encode())
            client.close(); upstream.close(); return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8899))
    srv.listen(50)
    srv.settimeout(30)
    print("relay listening 127.0.0.1:8899 -> upstream proxy "
          "(hosts: %s)" % ", ".join(ALLOWED_HOSTS))
    started = time.monotonic()
    while time.monotonic() - started < MAX_LIFETIME_SECONDS:
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    print("relay lifetime reached (%ss) — exiting"
          % MAX_LIFETIME_SECONDS)


if __name__ == "__main__":
    main()
