"""Phase 70 connection-pinning regression tests.

core.ssrf.assert_public_url used to be the whole defense: it
resolved + validated, returned, and the caller fetched with plain
urllib — which resolved the host AGAIN. A hostile DNS operator
could answer the second lookup differently (DNS rebinding) and
walk the fetch onto a private address despite the check.

The fix is connection pinning: the pinned connection classes in
core/ssrf.py resolve ONCE, inside connect(), validate every
address, and connect the socket to a validated address
themselves. These tests prove the window is closed:

* TestRebinding — a resolver that answers public first and
  private on any later lookup: the pinned fetch resolves exactly
  once, connects only to the validated public address, and the
  private answer is never even consulted.
* TestFailClosed — private-only and mixed resolutions are refused
  before ANY connection attempt; literal private IPs are refused
  without consulting the resolver at all.
* TestRedirectPinning — a redirect to a host resolving private is
  refused at the redirect hop's own connect.
* TestHostnameSemantics — pinning does not rewrite identity: the
  Host header carries the hostname, and the TLS wrap gets
  server_hostname = the hostname while the socket connects to
  the validated IP (with the caller's timeout).
* TestAddressFallback — validated addresses are tried in order.
* TestPinnedPlumbing — an end-to-end pinned GET against a real
  loopback server. PLUMBING ONLY: it stubs the resolver to
  loopback AND stubs the address-class check off, purely so the
  real socket path can run locally. The security properties are
  proven by the classes above, which never stub the check.

The socket seam is socket.create_connection (what the pinned
connect uses per validated address), stubbed with a recorder
that hands back FakeSockets serving canned HTTP responses.

Run:  python3 -m unittest discover -s tests
"""

import io
import ipaddress
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import ssrf  # noqa: E402

PUBLIC_IP = "93.184.216.34"
SECOND_PUBLIC_IP = "93.184.216.35"
METADATA_IP = "169.254.169.254"
OK_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def ip(text):
    return ipaddress.ip_address(text)


class FakeSocket:
    """A socket stand-in sufficient for http.client: it records
    everything sent and serves one canned HTTP response."""

    def __init__(self, response=OK_RESPONSE):
        self._response = response
        self._stream = None
        self.sent = b""
        self._timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self._timeout = timeout

    def gettimeout(self):
        return self._timeout

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        pass

    def sendall(self, data):
        self.sent += data

    def makefile(self, mode, buffering=None, **kwargs):
        if self._stream is None:
            self._stream = io.BytesIO(self._response)
        return self._stream

    def close(self):
        self.closed = True


class ConnectRecorder:
    """socket.create_connection stand-in: records every attempted
    (address, timeout) and returns FakeSockets — queued canned
    responses first, the default 200 afterwards."""

    def __init__(self, responses=()):
        self.calls = []
        self.sockets = []
        self._responses = list(responses)

    def __call__(self, address, timeout=None, source_address=None,
                 **kwargs):
        self.calls.append((address, timeout))
        response = self._responses.pop(0) if self._responses \
            else OK_RESPONSE
        sock = FakeSocket(response)
        self.sockets.append(sock)
        return sock

    def addresses(self):
        return [address for address, _timeout in self.calls]


def stub_resolver(answers):
    """answers: {host: [ipaddress, ...]} or one list for any host."""
    if isinstance(answers, dict):
        return mock.patch.object(
            ssrf, "resolve_host", lambda host: answers[host])
    return mock.patch.object(
        ssrf, "resolve_host", lambda host: answers)


class TestRebinding(unittest.TestCase):
    def test_rebinding_answer_is_never_consulted(self):
        resolutions = []

        def flip_flop(host):
            resolutions.append(host)
            if len(resolutions) == 1:
                return [ip(PUBLIC_IP)]
            # The rebinding answer: only reachable if the fetch
            # resolves a second time — the bug being pinned shut.
            return [ip(METADATA_IP)]

        recorder = ConnectRecorder()
        with mock.patch.object(ssrf, "resolve_host", flip_flop), \
                mock.patch.object(socket, "create_connection", recorder):
            with ssrf.pinned_urlopen(
                    "http://rebind.example/optout", timeout=7) as resp:
                status = resp.status
                body = resp.read()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        # Exactly one resolution happened — inside connect().
        self.assertEqual(resolutions, ["rebind.example"])
        # The one connection went to the validated public address,
        # with the caller's timeout; the private answer was never
        # connected to (it was never even produced).
        self.assertEqual(recorder.calls, [((PUBLIC_IP, 80), 7)])
        self.assertNotIn((METADATA_IP, 80), recorder.addresses())
        self.assertNotIn((METADATA_IP, 443), recorder.addresses())

    def test_host_header_carries_the_hostname_not_the_ip(self):
        recorder = ConnectRecorder()
        with stub_resolver([ip(PUBLIC_IP)]), \
                mock.patch.object(socket, "create_connection", recorder):
            with ssrf.pinned_urlopen(
                    "http://rebind.example/optout", timeout=5) as resp:
                resp.read()
        sent = recorder.sockets[0].sent
        self.assertIn(b"GET /optout HTTP/1.1", sent)
        self.assertIn(b"Host: rebind.example\r\n", sent)
        self.assertNotIn(b"Host: " + PUBLIC_IP.encode(), sent)


class TestFailClosed(unittest.TestCase):
    def test_private_only_resolution_blocked(self):
        recorder = ConnectRecorder()
        with stub_resolver([ip("10.0.0.5")]), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "https://broker.example/optout", timeout=5)
        self.assertEqual(recorder.calls, [])

    def test_mixed_resolution_blocked(self):
        # One public + one private: fail-closed, zero attempts —
        # a resolver that mixes answers must not get to choose
        # which one the connection lands on.
        recorder = ConnectRecorder()
        with stub_resolver([ip(PUBLIC_IP), ip("192.168.1.20")]), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "http://broker.example/optout", timeout=5)
        self.assertEqual(recorder.calls, [])

    def test_link_local_resolution_blocked(self):
        recorder = ConnectRecorder()
        with stub_resolver([ip(METADATA_IP)]), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "http://broker.example/optout", timeout=5)
        self.assertEqual(recorder.calls, [])

    def test_literal_private_ip_blocked_without_resolving(self):
        def explode(host):
            raise AssertionError("resolver used for a literal IP")
        recorder = ConnectRecorder()
        with mock.patch.object(ssrf, "resolve_host", explode), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen("http://127.0.0.1:9/admin", timeout=5)
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "https://169.254.169.254/latest/meta-data", timeout=5)
        self.assertEqual(recorder.calls, [])

    def test_unresolvable_host_blocked(self):
        def dead(host):
            raise socket.gaierror("no such host")
        recorder = ConnectRecorder()
        with mock.patch.object(ssrf, "resolve_host", dead), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "https://gone.example/optout", timeout=5)
        self.assertEqual(recorder.calls, [])


class TestRedirectPinning(unittest.TestCase):
    def test_redirect_to_private_host_blocked_at_second_hop(self):
        answers = {"good.example": [ip(PUBLIC_IP)],
                   "evil.example": [ip(METADATA_IP)]}
        redirect = (b"HTTP/1.1 302 Found\r\n"
                    b"Location: http://evil.example/landing\r\n"
                    b"Content-Length: 0\r\n\r\n")
        recorder = ConnectRecorder(responses=[redirect])
        with stub_resolver(answers), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "http://good.example/start", timeout=5)
        # The first hop connected (public); the redirect target was
        # refused at ITS connect — no second connection exists.
        self.assertEqual(recorder.addresses(), [(PUBLIC_IP, 80)])

    def test_redirect_to_public_host_still_works(self):
        answers = {"good.example": [ip(PUBLIC_IP)],
                   "also-good.example": [ip(SECOND_PUBLIC_IP)]}
        redirect = (b"HTTP/1.1 302 Found\r\n"
                    b"Location: http://also-good.example/final\r\n"
                    b"Content-Length: 0\r\n\r\n")
        recorder = ConnectRecorder(responses=[redirect])
        with stub_resolver(answers), \
                mock.patch.object(socket, "create_connection", recorder):
            with ssrf.pinned_urlopen(
                    "http://good.example/start", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read(), b"ok")
        self.assertEqual(recorder.addresses(),
                         [(PUBLIC_IP, 80), (SECOND_PUBLIC_IP, 80)])
        self.assertIn(b"Host: also-good.example\r\n",
                      recorder.sockets[1].sent)


class _RecordingContext:
    """SSLContext stand-in: records the wrap and passes the socket
    through unwrapped (the TLS layer is not what is under test —
    the server_hostname handed to it is)."""

    def __init__(self):
        self.wrapped = []

    def wrap_socket(self, sock, server_hostname=None):
        self.wrapped.append((sock, server_hostname))
        return sock


class TestHostnameSemantics(unittest.TestCase):
    def test_https_connects_to_ip_but_verifies_the_hostname(self):
        recorder = ConnectRecorder()
        with stub_resolver([ip(PUBLIC_IP)]), \
                mock.patch.object(socket, "create_connection", recorder):
            conn = ssrf.PinnedHTTPSConnection(
                "broker.example", 443, timeout=7)
            context = _RecordingContext()
            conn._context = context
            try:
                conn.connect()
            finally:
                conn.close()
        # TCP went to the validated IP, on the HTTPS port, with
        # the connection's timeout...
        self.assertEqual(recorder.calls, [((PUBLIC_IP, 443), 7)])
        # ...but the TLS wrap was told the HOSTNAME, so SNI and
        # certificate verification check broker.example, not the IP.
        self.assertEqual(len(context.wrapped), 1)
        self.assertEqual(context.wrapped[0][1], "broker.example")
        # And the connection object itself still names the host, so
        # http.client derives the Host header from the hostname.
        self.assertEqual(conn.host, "broker.example")

    def test_https_private_resolution_blocked(self):
        recorder = ConnectRecorder()
        with stub_resolver([ip("172.16.0.8")]), \
                mock.patch.object(socket, "create_connection", recorder):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.pinned_urlopen(
                    "https://broker.example/optout", timeout=5)
        self.assertEqual(recorder.calls, [])


class TestAddressFallback(unittest.TestCase):
    def test_validated_addresses_tried_in_order(self):
        attempts = []

        def flaky(address, timeout=None, source_address=None, **kw):
            attempts.append(address)
            if address[0] == PUBLIC_IP:
                raise OSError("connection refused")
            return FakeSocket()

        with stub_resolver([ip(PUBLIC_IP), ip(SECOND_PUBLIC_IP)]), \
                mock.patch.object(socket, "create_connection", flaky):
            with ssrf.pinned_urlopen(
                    "http://broker.example/optout", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        self.assertEqual(attempts,
                         [(PUBLIC_IP, 80), (SECOND_PUBLIC_IP, 80)])


class _PlumbingHandler(BaseHTTPRequestHandler):
    seen = {}

    def do_GET(self):
        type(self).seen = {"host": self.headers.get("Host"),
                            "path": self.path}
        body = b"pinned plumbing works"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestPinnedPlumbing(unittest.TestCase):
    def test_end_to_end_get_against_local_server(self):
        # PLUMBING ONLY: the resolver stub maps the test hostname
        # to loopback and the address-class check is stubbed off,
        # purely so the real socket path can run against a local
        # server. This proves the pinned machinery (handler ->
        # connection -> real TCP -> real HTTP) carries a request;
        # the security properties are proven by the classes above,
        # which do NOT stub the check.
        server = ThreadingHTTPServer(("127.0.0.1", 0), _PlumbingHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever,
                                  daemon=True)
        thread.start()
        try:
            with mock.patch.object(
                    ssrf, "resolve_host",
                    lambda host: [ip("127.0.0.1")]), \
                    mock.patch.object(ssrf, "_is_public",
                                      lambda addr: True):
                with ssrf.pinned_urlopen(
                        "http://plumbing.example:%d/hello" % port,
                        timeout=10) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read(),
                                     b"pinned plumbing works")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(_PlumbingHandler.seen["path"], "/hello")
        # The server saw the hostname (with its non-default port)
        # as Host — not the loopback address it was pinned to.
        self.assertEqual(_PlumbingHandler.seen["host"],
                         "plumbing.example:%d" % port)


if __name__ == "__main__":
    unittest.main()
