"""Validate identity-based Cloudflare Access assertions at the private origin.

Only the configured team JWKS is fetched. Token claims and headers never select
a remote key URL, an algorithm, or a default owner.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import json
import re
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")
_TEAM = re.compile(rf"{_LABEL}\.cloudflareaccess\.com\Z")
_KID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_AUDIENCE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@" + _LABEL + r"(?:\." + _LABEL + r")+\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z")
_REQUIRED = ("aud", "email", "exp", "iat", "nbf", "iss", "type", "sub")
_MAX_TOKEN = 16_384
_MAX_JWKS = 262_144
_CACHE_SECONDS = 300
_REFRESH_SECONDS = 30


class AccessDenied(ValueError):
    """An assertion cannot authorize this request; no token detail is exposed."""

    def __init__(self):
        super().__init__("A valid authorized Access session is required")


class AuthUnavailable(RuntimeError):
    """The configured key source is temporarily unusable; never fail open."""

    def __init__(self):
        super().__init__("Access verification is temporarily unavailable")


def validate_public_origin(public_origin: str) -> None:
    """Require the same explicit HTTPS DNS origin for every production adapter."""
    if not isinstance(public_origin, str) or not public_origin.startswith("https://"):
        raise ValueError("The public origin must be an explicit HTTPS origin")
    try:
        parsed = urlsplit(public_origin)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError("The public origin is invalid") from None
    if (not host or not _DOMAIN.fullmatch(host) or host.endswith(".localhost")
            or host.rsplit(".", 1)[-1].isdigit()
            or parsed.path or parsed.query or parsed.fragment or parsed.username is not None
            or parsed.password is not None or parsed.scheme != "https"
            or public_origin != "https://" + parsed.netloc
            or parsed.netloc != host + (f":{port}" if port is not None else "")
            or (port is not None and (port == 443 or not 1 <= port <= 65535))):
        raise ValueError("The public origin must contain only a public DNS host and optional port")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("The public origin must use a DNS hostname")


def validate_owner(owner: str) -> None:
    if (not isinstance(owner, str) or not 1 <= len(owner) <= 200
            or any(ord(char) < 33 or ord(char) == 127 for char in owner)):
        raise ValueError("One explicit internal owner is required")


@dataclass(frozen=True)
class AccessConfig:
    public_origin: str
    team_domain: str
    audience: str
    allowed_email: str
    owner: str = "local"

    def __post_init__(self):
        validate_public_origin(self.public_origin)
        if not isinstance(self.team_domain, str) or not _TEAM.fullmatch(self.team_domain):
            raise ValueError("The Access team domain must be <team>.cloudflareaccess.com")
        if not isinstance(self.audience, str) or not _AUDIENCE.fullmatch(self.audience):
            raise ValueError("An explicit Access application audience is required")
        if (not isinstance(self.allowed_email, str) or len(self.allowed_email) > 254
                or not _EMAIL.fullmatch(self.allowed_email)):
            raise ValueError("One explicit authorized email address is required")
        validate_owner(self.owner)

    @property
    def issuer(self) -> str:
        return "https://" + self.team_domain

    @property
    def jwks_url(self) -> str:
        return self.issuer + "/cdn-cgi/access/certs"


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON member")
        value[key] = item
    return value


def _nonfinite(value):
    raise ValueError("Nonfinite JSON number")


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_nonfinite)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AccessVerifier:
    """Bounded, thread-safe key cache for the configured single-owner Access app.

    ``fetch_keys`` is a zero-argument test seam returning a JWKS object. Production
    construction leaves it unset and uses only ``config.jwks_url`` over HTTPS.
    ``clock`` controls cache age, not JWT expiration (which uses wall-clock UTC).
    """

    def __init__(self, config: AccessConfig, *, fetch_keys=None, clock=time.monotonic):
        if not isinstance(config, AccessConfig):
            raise ValueError("A validated AccessConfig is required")
        self.config = config
        self._fetch_keys = self._fetch_default if fetch_keys is None else fetch_keys
        self._clock = clock
        self._keys = {}
        self._expires = float("-inf")
        self._next_refresh = float("-inf")
        self._lock = threading.Lock()

    def _fetch_default(self):
        request = Request(self.config.jwks_url, headers={"Accept": "application/json"})
        # Keep normal proxy/CA handling, but do not follow a redirect to another
        # service or accept an unbounded/chunked key document into memory.
        with build_opener(_NoRedirect()).open(request, timeout=3) as response:
            if response.status != 200 or response.geturl() != self.config.jwks_url:
                raise ValueError("Unexpected key source response")
            raw = response.read(_MAX_JWKS + 1)
        if len(raw) > _MAX_JWKS:
            raise ValueError("Key document exceeds its byte limit")
        return _json(raw)

    @staticmethod
    def _validated_keys(document):
        if (not isinstance(document, dict) or not isinstance(document.get("keys"), list)
                or not 1 <= len(document["keys"]) <= 16):
            raise ValueError("Invalid key set")
        keys = {}
        for item in document["keys"]:
            if not isinstance(item, dict):
                raise ValueError("Invalid key")
            kid = item.get("kid")
            if (not isinstance(kid, str) or not _KID.fullmatch(kid) or kid in keys
                    or item.get("kty") != "RSA" or item.get("alg") != "RS256"
                    or item.get("use") != "sig" or any(name in item for name in ("d", "p", "q", "dp", "dq", "qi", "oth"))
                    or not isinstance(item.get("n"), str) or not 1 <= len(item["n"]) <= 1400
                    or not isinstance(item.get("e"), str) or not 1 <= len(item["e"]) <= 16
                    or not _SEGMENT.fullmatch(item["n"]) or not _SEGMENT.fullmatch(item["e"])):
                raise ValueError("Invalid signing key")
            key = jwt.algorithms.RSAAlgorithm.from_jwk(item)
            if not isinstance(key, RSAPublicKey) or not 2048 <= key.key_size <= 8192:
                raise ValueError("Unsupported RSA key size")
            keys[kid] = key
        return keys

    def _key(self, kid):
        with self._lock:
            now = self._clock()
            if now < self._expires and kid in self._keys:
                return self._keys[kid]
            if now < self._next_refresh:
                if now < self._expires:
                    raise AccessDenied()
                raise AuthUnavailable()
            # Serialize refreshes and throttle failed fetches/unknown key IDs too.
            self._next_refresh = now + _REFRESH_SECONDS
            try:
                keys = self._validated_keys(self._fetch_keys())
            except Exception:
                # An old key cache keeps its original expiry; a failed refresh
                # never extends it and never makes this request authorized.
                raise AuthUnavailable() from None
            self._keys = keys
            self._expires = self._clock() + _CACHE_SECONDS
            if kid not in keys:
                raise AccessDenied()
            return keys[kid]

    def verify(self, assertion: str) -> dict:
        try:
            if (not isinstance(assertion, str) or not 1 <= len(assertion) <= _MAX_TOKEN
                    or not assertion.isascii()):
                raise ValueError("Invalid assertion")
            parts = assertion.split(".")
            if len(parts) != 3 or any(not _SEGMENT.fullmatch(part) for part in parts):
                raise ValueError("Invalid compact JWT")
            header, claims = [_json(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))) for part in parts[:2]]
            if (not isinstance(header, dict) or not isinstance(claims, dict)
                    or header.get("alg") != "RS256" or header.get("typ") != "JWT"
                    or not isinstance(header.get("kid"), str) or not _KID.fullmatch(header["kid"])
                    or any(name in header for name in ("crit", "b64", "jku", "jwk", "x5u"))
                    or any(name not in claims for name in _REQUIRED)):
                raise ValueError("Invalid token shape")
            if (claims["iss"] != self.config.issuer or claims["type"] != "app"
                    or claims["email"] != self.config.allowed_email
                    or not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 256
                    or any(ord(char) < 33 or ord(char) == 127 for char in claims["sub"])
                    or any(type(claims[name]) is not int for name in ("exp", "iat", "nbf"))
                    or claims["exp"] <= max(claims["iat"], claims["nbf"])):
                raise ValueError("Invalid identity claims")
            audience = claims["aud"]
            if isinstance(audience, str):
                audience = [audience]
            if (not isinstance(audience, list) or not 1 <= len(audience) <= 16
                    or any(not isinstance(item, str) or not _AUDIENCE.fullmatch(item) for item in audience)
                    or self.config.audience not in audience):
                raise ValueError("Invalid application audience")
        except Exception:
            raise AccessDenied() from None
        key = self._key(header["kid"])
        try:
            verified = jwt.decode(assertion, key, algorithms=["RS256"], audience=self.config.audience,
                                  issuer=self.config.issuer, options={"require": list(_REQUIRED)})
        except Exception:
            raise AccessDenied() from None
        return {"owner": self.config.owner, "email": verified["email"], "subject": verified["sub"]}
