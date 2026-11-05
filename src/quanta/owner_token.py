"""Explicit single-owner bearer authentication for a private HTTPS origin.

The configured token must be generated from 32 random bytes and supplied through
the host's private environment. This module never generates or returns a token.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import re

from .access_auth import validate_owner, validate_public_origin

_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class OwnerTokenDenied(ValueError):
    def __init__(self):
        super().__init__("A valid owner bearer token is required")


@dataclass(frozen=True)
class OwnerTokenConfig:
    public_origin: str
    token: str = field(repr=False)
    owner: str = "local"

    def __post_init__(self):
        validate_public_origin(self.public_origin)
        validate_owner(self.owner)
        if not isinstance(self.token, str) or not _TOKEN.fullmatch(self.token):
            raise ValueError("The owner token must contain exactly 64 lowercase hexadecimal characters")


class OwnerTokenVerifier:
    def __init__(self, config: OwnerTokenConfig):
        if not isinstance(config, OwnerTokenConfig):
            raise ValueError("A validated OwnerTokenConfig is required")
        self.config = config
        self._token = config.token.encode("ascii")

    def verify(self, authorization: str) -> dict:
        if not isinstance(authorization, str) or len(authorization) != 71 or not authorization.startswith("Bearer "):
            raise OwnerTokenDenied()
        try:
            candidate = authorization[7:].encode("ascii")
        except UnicodeEncodeError:
            raise OwnerTokenDenied() from None
        if not hmac.compare_digest(candidate, self._token):
            raise OwnerTokenDenied()
        return {"owner": self.config.owner}
