"""Directory parser: fixtures, wildcard, oos redirect, dedup, traceability."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture

from cyberx.evidence.parsers.directory import DirectoryParser
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.gaps import GapDetector
from cyberx.world.model import InMemoryWorldModel


def test_mixed_paths_and_redirect_target() -> None:
    artifact = artifact_from_fixture(
        "directory/mixed.json", adapter_name="directory_adapter", media_type="application/json"
    )
    obs = DirectoryParser().parse(artifact)
    statuses = {o.subject_hint: o.object for o in obs if o.predicate == "http.status"}
    assert statuses["url:http://10.10.11.23:80/admin"] == 200
    assert statuses["url:http://10.10.11.23:80/backup"] == 403
    assert statuses["url:http://10.10.11.23:80/uploads"] == 301
    assert statuses["url:http://10.10.11.23:80/missing"] == 404
    urls = {o.object for o in obs if o.predicate == "url.seen"}
    assert "url:http://10.10.11.23:80/login" in urls
    admin_seen = [o for o in obs if o.predicate == "url.seen" and o.object.endswith("/admin")]
    assert len(admin_seen) == 1


def test_wildcard_does_not_invent_paths() -> None:
    artifact = artifact_from_fixture(
        "directory/wildcard.json", adapter_name="directory_adapter", media_type="application/json"
    )
    obs = DirectoryParser().parse(artifact)
    assert len(obs) == 1
    assert obs[0].extra.get("wildcard_detected") is True
    assert obs[0].predicate == "url.seen"


def test_oos_redirect_does_not_create_external_url() -> None:
    artifact = artifact_from_fixture(
        "directory/redirect_oos.json",
        adapter_name="directory_adapter",
        media_type="application/json",
    )
    obs = DirectoryParser().parse(artifact)
    objects = [o.object for o in obs if o.predicate == "url.seen"]
    assert all("evil.example" not in str(item) for item in objects)
    assert any(str(item).endswith("/out") for item in objects)


def test_malformed_and_timeout_payloads() -> None:
    artifact = artifact_from_fixture(
        "directory/timeout.json", adapter_name="directory_adapter", media_type="application/json"
    )
    assert DirectoryParser().parse(artifact) == []


def test_world_dedup_and_gap_close() -> None:
    from cyberx.domain.ids import PREFIX_MISSION, new_id

    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    artifact = artifact_from_fixture(
        "directory/mixed.json",
        adapter_name="directory_adapter",
        media_type="application/json",
        mission_id=world.mission_id,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    assert evidence
    assert all(item.artifact_id == artifact.artifact_id for item in evidence)
    for item in evidence:
        world.apply_evidence(item)
    paths = {u.path for u in world.get_web_surfaces()}
    assert {"/admin", "/api", "/backup", "/uploads", "/login"} <= paths
    assert len([u for u in world.get_web_surfaces() if u.path == "/admin"]) == 1
    GapDetector().recompute(world)
    kinds = {g.kind for g in world.get_gaps() if not g.closed}
    assert "service.directories_unknown" not in kinds
    blob = " ".join(f.title.lower() for f in world.get_findings())
    assert "sql injection" not in blob
    assert "rce" not in blob
    _obs2, evidence2 = EvidencePipeline().normalize(artifact)
    for item in evidence2:
        world.apply_evidence(item)
    assert len([u for u in world.get_web_surfaces() if u.path == "/admin"]) == 1
