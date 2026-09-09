"""Filesystem artifact store. DB holds metadata only — never raw blobs."""

from __future__ import annotations

from pathlib import Path

from cyberx.domain.errors import StorageError
from cyberx.ports.execution import RawArtifact


class FileArtifactStore:
    def __init__(self, data_dir: str | Path) -> None:
        self._root = Path(data_dir)

    def mission_dir(self, mission_id: str) -> Path:
        path = self._root / "missions" / mission_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def path_for(self, artifact: RawArtifact) -> Path:
        folder = self.mission_dir(artifact.mission_id) / "artifacts"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"{artifact.artifact_id}.bin"

    def put(self, artifact: RawArtifact) -> str:
        dest = self.path_for(artifact)
        dest.write_bytes(artifact.body or b"")
        return str(dest)

    def get(self, artifact_id: str, mission_id: str) -> bytes:
        dest = self.mission_dir(mission_id) / "artifacts" / f"{artifact_id}.bin"
        if not dest.is_file():
            raise StorageError(
                f"artifact missing: {artifact_id}",
                code="artifact_missing",
            )
        return dest.read_bytes()
