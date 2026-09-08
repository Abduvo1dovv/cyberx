"""Deterministic HypothesisEngine. Hypotheses are not facts and never write claims."""

from __future__ import annotations

from cyberx.brain.types import HypothesisDelta
from cyberx.domain.models.findings import BrainContext

_TEMPLATES = {
    "host.unresolved": "hostname has not resolved to an address",
    "host.ports_unknown": "host ports have not been observed",
    "port.service_unknown": "open port has no service fingerprint",
    "service.http_unprobed": "http service has not been probed",
    "url.tech_unknown": "web surface technology is unknown",
    "domain.subdomains_unknown": "domain subdomains have not been enumerated",
    "service.directories_unknown": "http directories have not been enumerated",
    "endpoint.params_unknown": "endpoint parameters have not been observed",
}

_SIGNAL_TEMPLATES = {
    "auth_surface": "HTTP surface exposes an authentication boundary",
    "admin_surface": "HTTP surface exposes an administrative boundary",
    "tech_observed": "Technology fingerprint needs stronger evidence",
    "version_disclosure": "Exposed technology version needs confirmation",
    "unusual_service": "Unusual service fingerprint needs confirmation",
    "unusual_status": "Unusual HTTP behavior needs clarification",
    "unusual_redirect": "Redirect behavior needs in-scope confirmation",
}


class HypothesisEngine:
    def revise(self, ctx: BrainContext) -> list[HypothesisDelta]:
        existing = {row.get("statement") for row in ctx.hypotheses}
        existing_ids = {row.get("id") for row in ctx.hypotheses}
        del existing_ids
        deltas: list[HypothesisDelta] = []
        open_kinds = {g.get("kind") for g in ctx.gaps}
        for gap in ctx.gaps:
            kind = gap.get("kind") or ""
            template = _TEMPLATES.get(kind, f"unresolved knowledge: {kind}")
            subject = gap.get("subject_key") or gap.get("subject_id") or ""
            statement = f"{template} ({subject})" if subject else template
            if statement in existing:
                continue
            deltas.append(
                HypothesisDelta(
                    op="create",
                    statement=statement[:500],
                    gap_kind=kind,
                    gap_id=gap.get("id") or "",
                    subject_id=gap.get("subject_id") or "",
                    confidence=0.3,
                    rationale=f"open gap {kind}",
                )
            )
            existing.add(statement)
        for row in ctx.top_findings:
            signal = row.get("signal") or ""
            template = _SIGNAL_TEMPLATES.get(signal)
            if not template:
                continue
            fid = row.get("id") or ""
            statement = f"{template} ({fid})" if fid else template
            if statement in existing:
                continue
            deltas.append(
                HypothesisDelta(
                    op="create",
                    statement=statement[:500],
                    subject_id=row.get("asset_id") or "",
                    confidence=0.3,
                    rationale=f"recon signal {signal}",
                )
            )
            existing.add(statement)
        for row in ctx.validation_candidates:
            if row.get("status") != "supported":
                continue
            hid = row.get("hypothesis_id") or ""
            statement = ""
            for hyp in ctx.hypotheses:
                if hid and hyp.get("id") == hid:
                    statement = hyp.get("statement") or ""
                    break
            if not hid and not statement:
                continue
            deltas.append(
                HypothesisDelta(
                    op="support",
                    statement=statement or "validation evidence supports hypothesis",
                    hypothesis_id=hid or None,
                    confidence=0.45,
                    rationale="validation candidate supported by evidence",
                )
            )
        for row in ctx.hypotheses:
            statement = row.get("statement") or ""
            gap_derived = any(template in statement for template in _TEMPLATES.values())
            if not gap_derived:
                continue
            kind_hit = False
            for kind, template in _TEMPLATES.items():
                if template in statement and kind in open_kinds:
                    kind_hit = True
                    break
            if not kind_hit and statement:
                deltas.append(
                    HypothesisDelta(
                        op="retire",
                        statement=statement,
                        hypothesis_id=row.get("id"),
                        rationale="gap closed",
                    )
                )
        return deltas
