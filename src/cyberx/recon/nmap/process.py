"""Process runner for the Nmap adapter. The only recon module that launches processes."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

PROCESS_ERROR_MARKERS = (
    "could not bind",
    "failed to bind",
    "can't bind",
    "cannot bind",
    "permission denied",
    "operation not permitted",
    "requires root",
    "root privileges",
    "need to be root",
    "you requested a scan type which requires root",
    "nsock",
    "mksock_bind_addr",
    "fe80::",
    "bind to fe80",
)

NSOCK_BIND_MARKERS = (
    "nsock",
    "mksock_bind_addr",
    "fe80::",
    "bind to fe80",
)


def stderr_text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def looks_like_process_error(stderr: bytes | str | None) -> bool:
    text = stderr_text(stderr).lower()
    return any(marker in text for marker in PROCESS_ERROR_MARKERS)


def looks_like_nsock_bind_error(stderr: bytes | str | None) -> bool:
    """Dual-stack -e bind to IPv6 link-local. Distinct from generic bind/-S errors."""
    text = stderr_text(stderr).lower()
    return any(marker in text for marker in NSOCK_BIND_MARKERS)


def compact_stderr(stderr: bytes | str | None, *, limit: int = 200) -> str:
    text = stderr_text(stderr).replace("\r", "\n").strip()
    if not text:
        return ""
    line = text.split("\n", 1)[0].strip()
    return line[:limit]


@dataclass
class CommandResult:
    argv: list[str]
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    xml_path: str | None = None


class ProcessRunner:
    """Run an argv list. Never uses a shell."""

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: int,
        cwd: str | None = None,
    ) -> CommandResult:
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError("argv must be a non-empty list of strings")
        timeout = max(1, int(timeout_s))
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                cwd=cwd,
                capture_output=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except FileNotFoundError:
            return CommandResult(argv=list(argv), exit_code=127, stderr=b"executable not found")
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            return CommandResult(
                argv=list(argv),
                exit_code=-1,
                stdout=stdout if isinstance(stdout, bytes) else b"",
                stderr=stderr if isinstance(stderr, bytes) else b"",
                timed_out=True,
            )
        return CommandResult(
            argv=list(argv),
            exit_code=int(completed.returncode),
            stdout=completed.stdout or b"",
            stderr=completed.stderr or b"",
        )


class FixtureProcessRunner:
    """Test double. Writes provided XML to the -oX path. No real Nmap."""

    def __init__(
        self,
        xml: bytes,
        *,
        exit_code: int = 0,
        timed_out: bool = False,
        stderr: bytes = b"",
        missing_binary: bool = False,
    ) -> None:
        self.xml = xml
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.stderr = stderr
        self.missing_binary = missing_binary
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: int,
        cwd: str | None = None,
    ) -> CommandResult:
        del timeout_s, cwd
        self.calls.append(list(argv))
        if self.missing_binary:
            return CommandResult(argv=list(argv), exit_code=127, stderr=b"executable not found")
        xml_path = _output_path(argv)
        if xml_path and not self.timed_out:
            path = Path(xml_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.xml)
        return CommandResult(
            argv=list(argv),
            exit_code=self.exit_code,
            stdout=b"",
            stderr=self.stderr,
            timed_out=self.timed_out,
            xml_path=xml_path,
        )


def _output_path(argv: list[str]) -> str | None:
    if "-oX" not in argv:
        return None
    index = argv.index("-oX")
    if index + 1 >= len(argv):
        return None
    return argv[index + 1]
