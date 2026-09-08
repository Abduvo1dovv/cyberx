"""Prefix + Crockford ULID identifiers."""

from __future__ import annotations

import os
import re
import time

from cyberx.domain.errors import DomainValidationError

PREFIX_MISSION = "mis_"
PREFIX_TARGET = "tgt_"
PREFIX_SCOPE = "scp_"
PREFIX_ASSET = "ast_"
PREFIX_HOST = "hst_"
PREFIX_INTERFACE = "nif_"
PREFIX_PORT = "prt_"
PREFIX_SERVICE = "svc_"
PREFIX_TECH = "tec_"
PREFIX_DOMAIN = "dom_"
PREFIX_SUBDOMAIN = "sub_"
PREFIX_URL = "url_"
PREFIX_ENDPOINT = "ep_"
PREFIX_PARAMETER = "prm_"
PREFIX_AUTH = "aut_"
PREFIX_FINDING = "fnd_"
PREFIX_HYPOTHESIS = "hyp_"
PREFIX_VALIDATION = "val_"
PREFIX_PATH = "pth_"
PREFIX_EVIDENCE = "evd_"
PREFIX_OBSERVATION = "obs_"
PREFIX_ACTION = "act_"
PREFIX_TOOL_RUN = "run_"
PREFIX_RESULT = "res_"
PREFIX_TIMELINE = "tl_"
PREFIX_CLAIM = "clm_"
PREFIX_GAP = "gap_"
PREFIX_DECISION = "dec_"
PREFIX_ARTIFACT = "art_"

ALL_PREFIXES = frozenset(
    {
        PREFIX_MISSION,
        PREFIX_TARGET,
        PREFIX_SCOPE,
        PREFIX_ASSET,
        PREFIX_HOST,
        PREFIX_INTERFACE,
        PREFIX_PORT,
        PREFIX_SERVICE,
        PREFIX_TECH,
        PREFIX_DOMAIN,
        PREFIX_SUBDOMAIN,
        PREFIX_URL,
        PREFIX_ENDPOINT,
        PREFIX_PARAMETER,
        PREFIX_AUTH,
        PREFIX_FINDING,
        PREFIX_HYPOTHESIS,
        PREFIX_VALIDATION,
        PREFIX_PATH,
        PREFIX_EVIDENCE,
        PREFIX_OBSERVATION,
        PREFIX_ACTION,
        PREFIX_TOOL_RUN,
        PREFIX_RESULT,
        PREFIX_TIMELINE,
        PREFIX_CLAIM,
        PREFIX_GAP,
        PREFIX_DECISION,
        PREFIX_ARTIFACT,
    }
)

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PREFIX_ALT = "|".join(re.escape(p) for p in sorted(ALL_PREFIXES, key=len, reverse=True))
_ULID_RE = re.compile(rf"^({_PREFIX_ALT})[{_CROCKFORD}]{{26}}$")


def generate_ulid(*, timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Crockford-base32 ULID (26 chars)."""
    ts = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if ts < 0 or ts > 0xFFFFFFFFFFFF:
        raise DomainValidationError("ULID timestamp out of range")
    rand = randomness if randomness is not None else os.urandom(10)
    if len(rand) != 10:
        raise DomainValidationError("ULID randomness must be 10 bytes")
    val = (ts << 80) | int.from_bytes(rand, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[val & 31]
        val >>= 5
    return "".join(chars)


def new_id(prefix: str) -> str:
    if prefix not in ALL_PREFIXES:
        raise DomainValidationError(f"unknown id prefix: {prefix}")
    return prefix + generate_ulid()


def is_valid_id(value: str, expected_prefix: str | None = None) -> bool:
    if not isinstance(value, str) or not _ULID_RE.match(value):
        return False
    if expected_prefix is not None:
        return value.startswith(expected_prefix)
    return True


def require_id(value: str, expected_prefix: str | None = None) -> str:
    if not is_valid_id(value, expected_prefix):
        expected = expected_prefix or "known prefix + ULID"
        raise DomainValidationError(f"invalid id {value!r}, expected {expected}")
    return value
