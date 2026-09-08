"""Minimal DNS client. Stdlib UDP only. Closed record types. No shell."""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import normalize_fqdn, normalize_ip, validate_fqdn

RECORD_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {code: name for name, code in RECORD_TYPES.items()}
CLASS_IN = 1
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    values: list[str] = field(default_factory=list)
    rcode: str = "NOERROR"
    timed_out: bool = False
    error: str | None = None
    ttl: int | None = None


class DnsResolver(Protocol):
    def query(self, name: str, rtype: str, timeout_s: float) -> DnsAnswer: ...


class FixtureDnsResolver:
    """Offline resolver for tests. No network."""

    def __init__(self, answers: dict[tuple[str, str], DnsAnswer] | None = None) -> None:
        self._answers = dict(answers or {})
        self.queries: list[tuple[str, str]] = []

    def add(self, name: str, rtype: str, *values: str, rcode: str = "NOERROR") -> None:
        key = (normalize_fqdn(name), rtype.upper())
        self._answers[key] = DnsAnswer(name=key[0], rtype=key[1], values=list(values), rcode=rcode)

    def query(self, name: str, rtype: str, timeout_s: float) -> DnsAnswer:
        del timeout_s
        key = (normalize_fqdn(name), rtype.upper())
        self.queries.append(key)
        hit = self._answers.get(key)
        if hit is not None:
            return hit
        if any(owner == key[0] for owner, _kind in self._answers):
            return DnsAnswer(name=key[0], rtype=key[1], rcode="NOERROR")
        return DnsAnswer(name=key[0], rtype=key[1], rcode="NXDOMAIN")


class UdpDnsResolver:
    """One UDP query per call. System nameserver from resolv.conf when unset."""

    def __init__(self, nameserver: str | None = None, port: int = 53) -> None:
        self._nameserver = nameserver
        self._port = port

    def query(self, name: str, rtype: str, timeout_s: float) -> DnsAnswer:
        cleaned = validate_fqdn(name, allow_single_label=True)
        kind = rtype.upper()
        if kind not in RECORD_TYPES:
            return DnsAnswer(name=cleaned, rtype=kind, rcode="NOTIMP", error="unsupported_type")
        ident = random.randint(0, 65535)
        packet = encode_query(cleaned, kind, ident)
        server = self._nameserver or _system_nameserver()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(max(0.2, float(timeout_s)))
            sock.sendto(packet, (server, self._port))
            data, _addr = sock.recvfrom(4096)
        except TimeoutError:
            return DnsAnswer(
                name=cleaned, rtype=kind, rcode="TIMEOUT", timed_out=True, error="timeout"
            )
        except OSError as exc:
            return DnsAnswer(name=cleaned, rtype=kind, rcode="SERVFAIL", error=str(exc)[:80])
        finally:
            sock.close()
        try:
            return decode_response(data, cleaned, kind, ident)
        except Exception as exc:
            return DnsAnswer(name=cleaned, rtype=kind, rcode="FORMERR", error=str(exc)[:80])


def encode_query(name: str, rtype: str, ident: int) -> bytes:
    header = struct.pack("!HHHHHH", ident & 0xFFFF, 0x0100, 1, 0, 0, 0)
    qname = _encode_name(name)
    qtype = RECORD_TYPES[rtype.upper()]
    return header + qname + struct.pack("!HH", qtype, CLASS_IN)


def decode_response(
    packet: bytes, question_name: str, rtype: str, ident: int | None = None
) -> DnsAnswer:
    if len(packet) < 12:
        return DnsAnswer(name=question_name, rtype=rtype, rcode="FORMERR", error="short_packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if ident is not None and rid != ident:
        return DnsAnswer(name=question_name, rtype=rtype, rcode="FORMERR", error="id_mismatch")
    rcode = RCODE_NAMES.get(flags & 0xF, f"RCODE{flags & 0xF}")
    offset = 12
    for _ in range(qd):
        _name, offset = _decode_name(packet, offset)
        offset += 4
    values: list[str] = []
    ttl = None
    want = RECORD_TYPES[rtype.upper()]
    for _ in range(an):
        _owner, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            break
        atype, _aclass, attl, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlen]
        offset += rdlen
        ttl = attl if ttl is None else ttl
        if atype != want:
            continue
        parsed = _parse_rdata(atype, rdata, packet, offset - rdlen)
        if parsed:
            values.append(parsed)
    return DnsAnswer(name=question_name, rtype=rtype.upper(), values=values, rcode=rcode, ttl=ttl)


def query_records(
    resolver: DnsResolver,
    name: str,
    types: tuple[str, ...],
    timeout_s: float,
) -> list[DnsAnswer]:
    remaining = max(0.2, float(timeout_s))
    per = remaining / max(1, len(types))
    out: list[DnsAnswer] = []
    for rtype in types:
        answer = resolver.query(name, rtype, per)
        out.append(answer)
        if answer.timed_out:
            break
        if answer.rcode == "NXDOMAIN":
            break
    return out


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in normalize_fqdn(name).split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise IdentityError("invalid DNS label")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _decode_name(packet: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 16:
        raise IdentityError("dns name pointer loop")
    labels: list[str] = []
    jumped = False
    end = offset
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise IdentityError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            suffix, _ = _decode_name(packet, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            if not jumped:
                end = offset + 2
            jumped = True
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels).lower().rstrip("."), end


def _parse_rdata(atype: int, rdata: bytes, packet: bytes, offset: int) -> str | None:
    if atype == 1 and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if atype == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if atype in {2, 5}:
        try:
            name, _ = _decode_name(packet, offset)
        except Exception:
            return None
        return name
    if atype == 15 and len(rdata) >= 3:
        pref = struct.unpack("!H", rdata[:2])[0]
        try:
            exchange, _ = _decode_name(packet, offset + 2)
        except Exception:
            return None
        return f"{pref} {exchange}"
    if atype == 16:
        chunks: list[str] = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            chunks.append(rdata[i : i + ln].decode("utf-8", errors="replace"))
            i += ln
        return "".join(chunks)
    return None


def _system_nameserver() -> str:
    path = Path("/etc/resolv.conf")
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("nameserver"):
                parts = stripped.split()
                if len(parts) >= 2:
                    try:
                        return normalize_ip(parts[1])
                    except IdentityError:
                        continue
    except OSError:
        pass
    return "127.0.0.1"
