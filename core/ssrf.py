"""SSRF guard for outbound fetches whose URL comes from DATA
(spec Phase 70, depth pass).

`assert_public_url(url)` raises SsrfError unless the URL is
http/https AND every address its host resolves to is a public one.
It exists for the outbound points whose target is not a constant in
this codebase but arrives from data files or the registry:

  * agent.submit_form — the form action comes from a broker page /
    API caller (call sites additionally host-allowlist it against
    the broker registry; this guard is the second, independent
    check on the same path);
  * agent.probe_broker — the opt-out URL comes from brokers.json;
  * remediation verify 'direct' fetches — the URL template comes
    from verify_sources.json.

Fixed-host calls do NOT need it and do not use it: the provider
adapters (XposedOrNot, Have I Been Pwned), the DuckDuckGo index
endpoint, Brevo, Cloudflare DoH and crt.sh are constants chosen by
this codebase, not by data.

Connection pinning — the rebinding window, closed: an earlier
version of this guard resolved, checked, and returned, after
which the caller fetched with plain urllib — which resolved the
host AGAIN. A hostile DNS operator could answer the second lookup
differently (DNS rebinding) and walk the fetch onto
169.254.169.254, localhost, or the LAN despite the check. The
guarded fetch paths therefore no longer use plain urllib: they
use `pinned_urlopen` / `pinned_opener` (below), whose HTTP/HTTPS
connection classes resolve the host ONCE, inside connect(),
validate EVERY returned address with the same rules as
assert_public_url, and open the TCP connection to a validated
address themselves. The hostname is never re-resolved anywhere in
the fetch, so the only addresses ever connected to are ones
validated in that very connect() call. TLS stays honest while
pinned: the socket is wrapped with server_hostname = the original
hostname, so SNI and certificate verification still check the
hostname (never the pinned IP), and http.client derives the Host
header from the hostname as usual. Redirects re-enter the opener
per hop, so every redirect target is resolved and validated at
its own connect. The pinned opener deliberately ignores proxy
configuration (environment variables): a proxy would resolve the
hostname on its own side of the connection and reopen exactly the
window this closes. assert_public_url remains as the cheap
pre-check the call sites run first, so their existing refusal
shapes fire before any I/O; the pinning is the second, decisive
layer underneath it.

What pinning does NOT claim: validation happens per connection,
so a host whose DNS legitimately returns several public addresses
may be reached at any of them (all were validated in that
connect), and nothing here authenticates the CONTENT a validated
public server returns — judging that stays with the callers.

Fail-closed throughout: unresolvable hosts, empty resolutions,
non-http(s) schemes, credentials in the URL authority, and any
single non-public address in a mixed resolution all raise.
"""

import errno
import http.client
import ipaddress
import socket
import sys
import urllib.parse
import urllib.request


class SsrfError(ValueError):
    """The URL is not safe for this server to fetch."""


def resolve_host(host):
    """Resolve `host` to a list of ipaddress objects.

    This is the single patch point: tests stub this function to
    control what any hostname 'resolves to' without touching DNS.
    Raises socket.gaierror on resolution failure (callers in
    assert_public_url convert it to SsrfError)."""
    addresses = []
    for info in socket.getaddrinfo(host, None):
        raw = info[4][0]
        try:
            addresses.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    return addresses


def _is_public(ip):
    """True only for addresses the public internet could route to
    this server from. The six rejected classes are the Phase 70
    list; stdlib ipaddress already folds RFC1918, loopback and the
    benchmarking range into is_private."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _check_address(ip, url):
    if not _is_public(ip):
        raise SsrfError(
            "outbound URL resolves to a non-public address: %s" % url)


def assert_public_url(url):
    """Raise SsrfError unless `url` is http/https and its host —
    literal or resolved — is entirely public. Returns None."""
    if not isinstance(url, str) or not url.strip():
        raise SsrfError("outbound URL is empty")
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise SsrfError(
            "outbound URL scheme is not http/https: %s" % parsed.scheme)
    if parsed.username or parsed.password:
        raise SsrfError("outbound URL carries credentials")
    host = parsed.hostname
    if not host:
        raise SsrfError("outbound URL has no host")
    host = host.strip().rstrip(".")
    # Literal IP (v4 or v6): check it directly, no resolution.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        _check_address(literal, url)
        return
    try:
        addresses = resolve_host(host)
    except (socket.gaierror, UnicodeError) as exc:
        raise SsrfError(
            "outbound host does not resolve: %s" % host) from exc
    if not addresses:
        raise SsrfError("outbound host does not resolve: %s" % host)
    for ip in addresses:
        _check_address(ip, url)


# ---------------------------------------------------------------------------
# Connection pinning (see module docstring): resolve + validate +
# connect happen exactly once, inside connect(), so no second DNS
# lookup exists for a rebinding answer to poison.
# ---------------------------------------------------------------------------

def _validated_addresses(host):
    """Resolve `host` once and return its addresses, EVERY one
    validated public — the connect-time twin of assert_public_url.
    Literal IPs are validated directly, with no resolution. Raises
    SsrfError on any failure, exactly like the pre-check."""
    host = (host or "").strip().rstrip(".")
    if not host:
        raise SsrfError("outbound connection has no host")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        _check_address(literal, host)
        return [literal]
    try:
        addresses = resolve_host(host)
    except (socket.gaierror, UnicodeError) as exc:
        raise SsrfError(
            "outbound host does not resolve: %s" % host) from exc
    if not addresses:
        raise SsrfError("outbound host does not resolve: %s" % host)
    for ip in addresses:
        _check_address(ip, host)
    return addresses


def _connect_validated(host, port, timeout, source_address=None):
    """Open a TCP connection to one of `host`'s validated addresses.

    This is the ONLY resolution in a pinned fetch: the returned
    socket is connected to an address this call resolved and
    validated. Addresses are tried in resolver order; the first
    that connects wins, and if none connect, the last OSError
    propagates — the same failure shape a stock http.client
    connection would have produced."""
    last_error = None
    for ip in _validated_addresses(host):
        try:
            return socket.create_connection(
                (str(ip), port), timeout, source_address)
        except OSError as exc:
            last_error = exc
    raise last_error


def _tune_socket(sock):
    """The TCP_NODELAY step of http.client's own connect()."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError as exc:
        if exc.errno != errno.ENOPROTOOPT:
            raise


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose connect() resolves, validates, and
    pins. `self.host` stays the hostname, so the Host header and
    tunnel semantics are stock http.client — only the socket's
    destination is pinned to a validated address."""

    def connect(self):
        sys.audit("http.client.connect", self, self.host, self.port)
        self.sock = _connect_validated(
            self.host, self.port, self.timeout, self.source_address)
        _tune_socket(self.sock)
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS twin of PinnedHTTPConnection. The TLS wrap uses
    server_hostname = the original hostname (or the tunnel host,
    as stdlib does), so SNI and certificate verification check
    the hostname — never the pinned IP."""

    def connect(self):
        sys.audit("http.client.connect", self, self.host, self.port)
        self.sock = _connect_validated(
            self.host, self.port, self.timeout, self.source_address)
        _tune_socket(self.sock)
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=server_hostname)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """urllib HTTP handler that opens PinnedHTTPConnections."""

    def http_open(self, req):
        return self.do_open(PinnedHTTPConnection, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib HTTPS handler that opens PinnedHTTPSConnections,
    with the stdlib handler's context plumbing."""

    def https_open(self, req):
        return self.do_open(PinnedHTTPSConnection, req,
                            context=self._context)


def pinned_opener(*extra_handlers):
    """An opener whose http/https fetches are connection-pinned.

    Proxy handling is disabled on purpose (ProxyHandler({})): a
    proxy resolves the hostname on its own side of the connection,
    reopening the rebinding window. Caller handlers (e.g. a
    redirect policy) compose in via `extra_handlers`; otherwise
    the default redirect handler applies, and every redirect hop
    re-enters these pinned handlers, so each hop's target is
    resolved and validated at its own connect."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        PinnedHTTPHandler(), PinnedHTTPSHandler(), *extra_handlers)


_DEFAULT_OPENER = None


def pinned_urlopen(url, timeout=30):
    """urllib.request.urlopen replacement for guarded, data-driven
    fetches: the same request/response contract, but the
    connection is pinned (module docstring). Raises SsrfError when
    the target — the initial URL or any redirect hop — does not
    resolve entirely to public addresses; transport failures keep
    their stock shapes (URLError / HTTPError)."""
    global _DEFAULT_OPENER
    if _DEFAULT_OPENER is None:
        _DEFAULT_OPENER = pinned_opener()
    return _DEFAULT_OPENER.open(url, timeout=timeout)
