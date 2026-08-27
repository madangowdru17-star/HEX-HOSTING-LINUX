"""
Strict validation for the "import from GitHub" feature.

Goal: only ever let `git clone` talk to the real github.com over https,
for a well-formed owner/repo, never to an internal/private address that
an attacker could smuggle in via DNS rebinding, IP-literal hosts,
alternate ports, credentials-in-URL, or query/fragment tricks.
"""
import ipaddress
import re
import socket
from urllib.parse import urlsplit

_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_ALLOWED_HOST = "github.com"


class InvalidRepoURL(Exception):
    pass


def validate_github_url(url: str) -> str:
    """Return a normalized, safe https://github.com/<owner>/<repo>.git URL,
    or raise InvalidRepoURL with a human-readable reason."""
    if not url or len(url) > 300:
        raise InvalidRepoURL("URL is missing or too long.")

    parts = urlsplit(url.strip())

    if parts.scheme != "https":
        raise InvalidRepoURL("Only https:// GitHub URLs are allowed.")
    if parts.username or parts.password:
        raise InvalidRepoURL("Credentials in the URL are not allowed.")
    if parts.port not in (None, 443):
        raise InvalidRepoURL("Non-standard ports are not allowed.")
    if parts.hostname != _ALLOWED_HOST:
        raise InvalidRepoURL("Only repositories hosted on github.com are allowed.")
    if parts.query or parts.fragment:
        raise InvalidRepoURL("URL must not contain a query string or fragment.")

    path = parts.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not _OWNER_REPO_RE.match(path):
        raise InvalidRepoURL("URL must look like https://github.com/<owner>/<repo>.")
    if path.count("/") != 1:
        raise InvalidRepoURL("Only top-level owner/repo URLs are allowed (no sub-paths).")

    owner, repo = path.split("/")
    _assert_not_internal_ip(_ALLOWED_HOST)
    return f"https://github.com/{owner}/{repo}.git"


def _assert_not_internal_ip(hostname: str):
    """Resolve the hostname and refuse to proceed if *any* resolved
    address is private/loopback/link-local/reserved — guards against DNS
    rebinding pointing github.com at an internal service at clone time."""
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise InvalidRepoURL(f"Could not resolve {hostname}: {e}")

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            raise InvalidRepoURL("Refusing to clone: hostname resolves to a non-public address.")
