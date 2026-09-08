"""DNS JSON parser. NXDOMAIN / empty records → empty observations, not an error."""

from __future__ import annotations

from typing import Any

from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import domain_key, is_subdomain_of, subdomain_key, validate_fqdn
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import emit, host_subject, load_json_object
from cyberx.ports.execution import RawArtifact

PARSER_ID = "dns"
_NEGATIVE = frozenset({"nxdomain", "timeout", "servfail", "out_of_scope", "empty"})


class DnsParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = ("dns.record", "dns.subdomain", "host.address", "host.hostname")

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        return observations_from_dns_payload(load_json_object(artifact), artifact)


def observations_from_dns_payload(data: dict[str, Any], artifact: RawArtifact) -> list[Observation]:
    status = str(data.get("status") or "").lower()
    if status in _NEGATIVE and not data.get("records") and not data.get("subdomains"):
        return []

    out: list[Observation] = []
    fqdn = data.get("fqdn") or data.get("target") or artifact.source_locator
    zone = None
    if isinstance(fqdn, str) and fqdn.strip():
        try:
            zone = validate_fqdn(fqdn.strip(), allow_single_label=False)
        except IdentityError:
            try:
                zone = validate_fqdn(fqdn.strip(), allow_single_label=True)
            except IdentityError:
                zone = fqdn.strip().lower().rstrip(".")
    zone_hint = None
    if zone:
        try:
            zone_hint = domain_key(zone)
        except IdentityError:
            zone_hint = zone

    records = list(data.get("records") or [])
    for detail in data.get("details") or []:
        if isinstance(detail, dict):
            nested = detail.get("records") or []
            if isinstance(nested, list):
                records.extend(nested)
            elif isinstance(detail.get("fqdn"), str):
                pass

    if isinstance(records, list):
        for rec in records:
            if not isinstance(rec, dict):
                continue
            rtype = str(rec.get("type") or "").upper()
            name = str(rec.get("name") or fqdn or "").strip().lower().rstrip(".")
            value = rec.get("value")
            if not rtype or value is None:
                continue
            subject = zone_hint or name or "dns"
            obj: dict[str, Any] = {"type": rtype, "name": name, "value": str(value)}
            if rec.get("preference") is not None:
                obj["preference"] = str(rec.get("preference"))
            extra = {}
            if rec.get("out_of_scope"):
                extra["out_of_scope"] = True
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="dns.record",
                    obj=obj,
                    subject_hint=subject,
                    extra=extra or None,
                )
            )
            if rtype in {"A", "AAAA"}:
                try:
                    host = host_subject(str(value))
                except IdentityError:
                    continue
                out.append(
                    emit(
                        artifact=artifact,
                        parser_id=PARSER_ID,
                        predicate="host.address",
                        obj=str(value),
                        subject_hint=host,
                    )
                )
                if name:
                    out.append(
                        emit(
                            artifact=artifact,
                            parser_id=PARSER_ID,
                            predicate="host.hostname",
                            obj=name,
                            subject_hint=host,
                        )
                    )
            out.extend(_subdomain_obs(artifact, name, zone))
            if rtype in {"CNAME", "MX", "NS"}:
                target = str(value).strip().lower().rstrip(".")
                if " " in target:
                    target = target.split()[-1]
                out.extend(_subdomain_obs(artifact, target, zone))

    names = data.get("subdomains") or []
    if isinstance(names, list):
        for item in names:
            if isinstance(item, str):
                fq = item
            elif isinstance(item, dict):
                fq = item.get("fqdn")
            else:
                fq = None
            if not isinstance(fq, str) or not fq.strip():
                continue
            cleaned = fq.strip().lower().rstrip(".")
            out.extend(_subdomain_obs(artifact, cleaned, zone, force=True))
    return out


def _subdomain_obs(
    artifact: RawArtifact, name: str, zone: str | None, *, force: bool = False
) -> list[Observation]:
    if not name:
        return []
    try:
        cleaned = validate_fqdn(name, allow_single_label=False)
    except IdentityError:
        return []
    if zone:
        try:
            zone_n = validate_fqdn(zone, allow_single_label=False)
        except IdentityError:
            zone_n = zone
        if cleaned == zone_n and not force:
            return []
        if not is_subdomain_of(cleaned, zone_n):
            return []
    try:
        subject = subdomain_key(cleaned)
    except IdentityError:
        return []
    return [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="dns.subdomain",
            obj=cleaned,
            subject_hint=subject,
        )
    ]
