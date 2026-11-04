"""Real RSA assertions, identity boundaries, trusted key origin and cache failure."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import base64
import copy
import json
import time

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from quanta import access_auth
from quanta.access_auth import AccessConfig, AccessDenied, AccessVerifier, AuthUnavailable


@pytest.fixture(scope="module")
def key():
    # Ephemeral test key, never a deployed identity or stored credential.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def config():
    return AccessConfig("https://quanta.example.com", "quanta-test.cloudflareaccess.com",
                        "test-application-audience", "researcher@example.com")


def jwks(key, kid="current"):
    value = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    value.update(kid=kid, alg="RS256", use="sig")
    return {"keys": [value]}


def claims(config, **changes):
    now = int(time.time())
    value = {"aud": [config.audience], "email": config.allowed_email, "exp": now + 300,
             "iat": now - 1, "nbf": now - 1, "iss": config.issuer, "type": "app",
             "sub": "7335d417-61da-459d-899c-0a01c76a2f94"}
    value.update(changes)
    return value


def token(key, config, *, payload=None, kid="current", headers=None):
    return jwt.encode(claims(config) if payload is None else payload, key, algorithm="RS256",
                      headers={"kid": kid, **(headers or {})})


def test_config_binds_only_explicit_origin_team_audience_and_owner(config):
    assert config.issuer == "https://quanta-test.cloudflareaccess.com"
    assert config.jwks_url == config.issuer + "/cdn-cgi/access/certs"
    assert config.owner == "local"
    with pytest.raises(AttributeError):
        config.owner = "other"


@pytest.mark.parametrize("origin", [
    "http://quanta.example.com", "https://localhost", "https://dev.localhost",
    "https://127.0.0.1", "https://127.1", "https://[::1]",
    "https://user:password@quanta.example.com", "https://quanta.example.com/",
    "https://quanta.example.com?", "https://quanta.example.com#",
    "https://quanta.example.com/path", "https://quanta.example.com:0",
    "https://quanta.example.com:443",
])
def test_invalid_origin_cannot_be_used_for_production_auth(origin, config):
    with pytest.raises(ValueError):
        AccessConfig(origin, config.team_domain, config.audience, config.allowed_email)


def test_nondefault_https_origin_port_remains_explicit(config):
    explicit = AccessConfig("https://quanta.example.com:8443", config.team_domain,
                            config.audience, config.allowed_email)
    assert explicit.public_origin == "https://quanta.example.com:8443"


@pytest.mark.parametrize("field,value", [
    ("team_domain", "https://quanta-test.cloudflareaccess.com"),
    ("team_domain", "quanta-test.cloudflareaccess.com.attacker.example"),
    ("team_domain", "attacker.example"), ("audience", ""),
    ("allowed_email", ""), ("allowed_email", "a@example.com,b@example.com"),
    ("owner", ""), ("owner", "local\nother"),
])
def test_incomplete_or_ambiguous_auth_config_is_refused(field, value, config):
    arguments = dict(vars(config), **{field: value})
    with pytest.raises(ValueError):
        AccessConfig(**arguments)


def test_valid_application_assertion_maps_only_verified_identity(config, key):
    verifier = AccessVerifier(config, fetch_keys=lambda: jwks(key))
    assert verifier.verify(token(key, config)) == {
        "owner": "local", "email": config.allowed_email,
        "subject": "7335d417-61da-459d-899c-0a01c76a2f94"}
    asserted_owner = claims(config, owner="another-owner", role="administrator")
    assert verifier.verify(token(key, config, payload=asserted_owner))["owner"] == "local"


@pytest.mark.parametrize("change", [
    {"aud": ["different-application"]}, {"iss": "https://attacker.example"},
    {"type": "org"}, {"email": "other@example.com"}, {"sub": ""},
    {"sub": 123}, {"iat": True}, {"exp": "9999999999"}, {"nbf": float("nan")},
])
def test_invalid_identity_shape_is_rejected_without_key_fetch(config, key, change):
    calls = []
    verifier = AccessVerifier(config, fetch_keys=lambda: calls.append(True))
    with pytest.raises(AccessDenied, match="^A valid authorized Access session is required$"):
        verifier.verify(token(key, config, payload=claims(config, **change)))
    assert calls == []


@pytest.mark.parametrize("missing", ["aud", "email", "exp", "iat", "nbf", "iss", "type", "sub"])
def test_identity_application_claims_are_required(config, key, missing):
    payload = claims(config)
    del payload[missing]
    with pytest.raises(AccessDenied):
        AccessVerifier(config, fetch_keys=lambda: pytest.fail("Missing claim fetched keys")).verify(
            token(key, config, payload=payload))


@pytest.mark.parametrize("change", [
    {"exp": int(time.time()) - 1}, {"nbf": int(time.time()) + 100},
    {"iat": int(time.time()) + 100},
])
def test_signed_but_expired_or_not_yet_valid_tokens_are_denied(config, key, change):
    verifier = AccessVerifier(config, fetch_keys=lambda: jwks(key))
    with pytest.raises(AccessDenied):
        verifier.verify(token(key, config, payload=claims(config, **change)))


def test_signature_and_fixed_algorithm_are_both_required(config, key):
    verifier = AccessVerifier(config, fetch_keys=lambda: jwks(key))
    forged = jwt.encode(claims(config), "untrusted-test-secret-which-is-long-enough", algorithm="HS256",
                        headers={"kid": "current"})
    with pytest.raises(AccessDenied):
        verifier.verify(forged)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AccessDenied):
        verifier.verify(token(other, config))


@pytest.mark.parametrize("headers", [{"jku": "https://attacker.example/keys"},
                                     {"jwk": {"kty": "RSA"}}, {"x5u": "https://attacker.example/key"},
                                     {"crit": ["test"]}, {"typ": "not-JWT"}])
def test_token_headers_cannot_choose_remote_keys_or_extensions(config, key, headers):
    with pytest.raises(AccessDenied):
        AccessVerifier(config, fetch_keys=lambda: pytest.fail("Untrusted header fetched keys")).verify(
            token(key, config, headers=headers))


@pytest.mark.parametrize("value", [None, "", "Bearer token", "a.b.c", "a.b", "é", "a" * 16385])
def test_malformed_or_oversized_assertions_never_fetch_keys(config, value):
    with pytest.raises(AccessDenied):
        AccessVerifier(config, fetch_keys=lambda: pytest.fail("Malformed assertion fetched keys")).verify(value)


def test_duplicate_claim_or_header_members_are_rejected_before_network(config, key):
    assertion = token(key, config)
    original = assertion.split(".")
    for part in (0, 1):
        parts = original.copy()
        raw = base64.urlsafe_b64decode(parts[part] + "=" * (-len(parts[part]) % 4)).decode()
        duplicate = ',"alg":"RS256"}' if part == 0 else ',"email":"researcher@example.com"}'
        parts[part] = base64.urlsafe_b64encode((raw[:-1] + duplicate).encode()).decode().rstrip("=")
        verifier = AccessVerifier(config, fetch_keys=lambda: pytest.fail("Duplicate JSON fetched keys"))
        with pytest.raises(AccessDenied):
            verifier.verify(".".join(parts))


def test_unknown_key_ids_and_failed_fetches_are_throttled(config, key):
    now, calls = [100.0], []
    def unavailable():
        calls.append(now[0])
        raise OSError("private diagnostic must not reach caller")
    verifier = AccessVerifier(config, fetch_keys=unavailable, clock=lambda: now[0])
    for unused in range(5):
        with pytest.raises(AuthUnavailable, match="^Access verification is temporarily unavailable$"):
            verifier.verify(token(key, config))
    assert calls == [100.0]
    now[0] += 30
    with pytest.raises(AuthUnavailable):
        verifier.verify(token(key, config))
    assert calls == [100.0, 130.0]


def test_cache_rotation_and_expiration_fail_closed(config, key):
    now, calls = [0.0], []
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    source = [jwks(key)]
    def fetch():
        calls.append(now[0])
        if source[0] is None:
            raise OSError("offline")
        return copy.deepcopy(source[0])
    verifier = AccessVerifier(config, fetch_keys=fetch, clock=lambda: now[0])
    first, rotated = token(key, config), token(second, config, kid="rotated")
    verifier.verify(first)
    with pytest.raises(AccessDenied):
        verifier.verify(rotated)
    assert calls == [0.0]
    now[0] = 30
    source[0] = {"keys": jwks(key)["keys"] + jwks(second, "rotated")["keys"]}
    verifier.verify(rotated)
    verifier.verify(first)
    assert calls == [0.0, 30]
    source[0] = None
    now[0] = 329
    verifier.verify(rotated)
    now[0] = 330
    with pytest.raises(AuthUnavailable):
        verifier.verify(rotated)
    now[0] = 331
    with pytest.raises(AuthUnavailable):
        verifier.verify(first)
    assert calls == [0.0, 30, 330]


def test_concurrent_initial_requests_share_one_bounded_key_fetch(config, key):
    calls = []
    def fetch():
        calls.append(True)
        return jwks(key)
    verifier = AccessVerifier(config, fetch_keys=fetch)
    assertion = token(key, config)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(verifier.verify, [assertion] * 16))
    assert len(calls) == 1
    assert all(result["owner"] == "local" for result in results)


@pytest.mark.parametrize("mutation", ["duplicate", "too_many", "wrong_alg", "wrong_use", "private", "weak"])
def test_invalid_or_ambiguous_jwks_is_unavailable(config, key, mutation):
    value = jwks(key)
    if mutation == "duplicate": value["keys"] *= 2
    elif mutation == "too_many": value["keys"] *= 17
    elif mutation == "wrong_alg": value["keys"][0]["alg"] = "HS256"
    elif mutation == "wrong_use": value["keys"][0]["use"] = "enc"
    elif mutation == "private": value["keys"][0]["d"] = "untrusted"
    else: value = jwks(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(AuthUnavailable):
        AccessVerifier(config, fetch_keys=lambda: value).verify(token(key, config))


def test_default_fetch_uses_only_configured_https_url_and_bounded_read(config, monkeypatch):
    seen = {}
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def geturl(self): return config.jwks_url
        def read(self, count):
            seen["read"] = count
            return b'{"keys": []}'
    class Opener:
        def open(self, request, timeout):
            seen.update(url=request.full_url, timeout=timeout)
            return Response()
    monkeypatch.setattr(access_auth, "build_opener", lambda handler: Opener())
    assert AccessVerifier(config)._fetch_default() == {"keys": []}
    assert seen == {"url": config.jwks_url, "timeout": 3, "read": 262145}
    assert access_auth._NoRedirect().redirect_request(None, None, 302, None, None,
                                                    "https://attacker.example") is None


def test_default_fetch_rejects_oversized_and_duplicate_key_documents(config, monkeypatch):
    content = [b'{"keys": [], "keys": []}']
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def geturl(self): return config.jwks_url
        def read(self, count): return content[0]
    class Opener:
        def open(self, request, timeout): return Response()
    monkeypatch.setattr(access_auth, "build_opener", lambda handler: Opener())
    with pytest.raises(ValueError): AccessVerifier(config)._fetch_default()
    content[0] = b"x" * 262145
    with pytest.raises(ValueError): AccessVerifier(config)._fetch_default()
