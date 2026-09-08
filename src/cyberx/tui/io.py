"""Console IO ports. ScriptedIO is the test double; StdIO is the process console."""

from __future__ import annotations

import sys
from typing import Protocol, TextIO


class ConsoleIO(Protocol):
    color: bool

    def write(self, text: str) -> None: ...

    def write_line(self, text: str = "") -> None: ...

    def read_line(self, prompt: str = "") -> str | None: ...

    def read_key(self, prompt: str = "") -> str | None: ...

    def poll_key(self) -> str | None: ...

    def clear(self) -> None: ...


class ScriptedIO:
    """Deterministic IO for tests. Lines are consumed in order."""

    def __init__(self, lines: list[str] | None = None, *, color: bool = False) -> None:
        self._lines = list(lines or [])
        self.output: list[str] = []
        self.color = color

    def write(self, text: str) -> None:
        self.output.append(text)

    def write_line(self, text: str = "") -> None:
        self.output.append(text + "\n")

    def read_line(self, prompt: str = "") -> str | None:
        if prompt:
            self.output.append(prompt)
        if not self._lines:
            return None
        return self._lines.pop(0)

    def read_key(self, prompt: str = "") -> str | None:
        line = self.read_line(prompt)
        if line is None:
            return None
        text = line.strip()
        return text[:1].lower() if text else ""

    def poll_key(self) -> str | None:
        if not self._lines:
            return None
        return self.read_key("")

    def clear(self) -> None:
        return None

    def text(self) -> str:
        return "".join(self.output)


class StdIO:
    def __init__(
        self,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        *,
        color: bool | None = None,
    ) -> None:
        self._in = stdin or sys.stdin
        self._out = stdout or sys.stdout
        if color is None:
            self.color = bool(getattr(self._out, "isatty", lambda: False)())
        else:
            self.color = color

    def write(self, text: str) -> None:
        self._out.write(text)
        self._out.flush()

    def write_line(self, text: str = "") -> None:
        self._out.write(text + "\n")
        self._out.flush()

    def read_line(self, prompt: str = "") -> str | None:
        if prompt:
            self.write(prompt)
        try:
            line = self._in.readline()
        except EOFError:
            return None
        if line == "":
            return None
        return line.rstrip("\n")

    def read_key(self, prompt: str = "") -> str | None:
        line = self.read_line(prompt)
        if line is None:
            return None
        text = line.strip()
        return text[:1].lower() if text else ""

    def poll_key(self) -> str | None:
        return None

    def clear(self) -> None:
        if self.color:
            self.write("\033[2J\033[H")
