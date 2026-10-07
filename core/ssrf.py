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

Honest residual: the guard resolves, checks, and returns — the
caller then fetches, which resolves AGAIN. A hostile DNS operator
could answer differently on the second lookup (DNS rebinding), so
this kills the naive/internal-target class — a data file or a
compromised registry pointing the server at 169.254.169.254,
localhost, or the LAN — but it is not connection pinning. Pinning
would mean fetching by validated IP with SNI/Host rewriting, which
breaks TLS verification for the brokers we legitimately fetch;
that trade is documented, not hidden.

Fail-closed throughout: unresolvable hosts, empty resolutions,
non-http(s) schemes, credentials in the URL authority, and any
single non-public address in a mixed resolution all raise.
"""

import ipaddress
import socket
import urllib.parse


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
