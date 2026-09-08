"""Operator console application. No domain logic; facade only."""

from __future__ import annotations

from cyberx.app.errors import operator_message
from cyberx.app.facade import OperatorFacade
from cyberx.app.views import DashboardView
from cyberx.tui.io import ConsoleIO, StdIO
from cyberx.tui.keys import BINDINGS, HELP_TEXT
from cyberx.tui.render import (
    render_banner,
    render_dashboard,
    render_findings,
    render_graph,
    render_hypotheses,
    render_investigations,
    render_logs,
    render_mission_header,
    render_network,
    render_scope,
    render_world,
)


class ConsoleApp:
    def __init__(self, facade: OperatorFacade, io: ConsoleIO | None = None) -> None:
        self._facade = facade
        self._io = io or StdIO()
        self._auto = False

    def run(self) -> int:
        self._io.write(render_banner(self._io.color))
        try:
            mission_id = self._select_or_create()
            if not mission_id:
                self._io.write_line("Goodbye.")
                return 0
            return self._dashboard_loop(mission_id)
        except KeyboardInterrupt:
            self._io.write_line("\nInterrupted.")
            return 0

    def _select_or_create(self) -> str | None:
        resumable = self._facade.list_resumable()
        if resumable:
            self._io.write_line("Resumable missions:")
            for idx, item in enumerate(resumable, start=1):
                self._io.write_line(
                    f"  {idx}) {item.name}  {item.status}  {item.target}  {item.mission_id}"
                )
            choice = self._ask(" [1] new mission  [2] resume: ")
            if choice is None:
                return None
            if choice.strip() == "2":
                return self._pick_resume(resumable)
        return self._wizard()

    def _pick_resume(self, resumable: tuple) -> str | None:
        raw = self._ask("Resume which #? ")
        if raw is None:
            return None
        try:
            idx = int(raw.strip()) - 1
            return resumable[idx].mission_id
        except (ValueError, IndexError):
            self._io.write_line("Invalid selection.")
            return None

    def _wizard(self) -> str | None:
        target = self._ask_required("Target: ")
        if target is None:
            return None
        name = self._ask_required("Mission name: ")
        if name is None:
            return None
        intent = self._ask_required("Intent: ")
        if intent is None:
            return None
        self._io.write_line("Mode:  1) ctf  2) lab  3) authorized_assessment (professional)")
        mode = self._ask("Mode [1]: ")
        if mode is None:
            return None
        mode = mode.strip() or "1"
        options = self._facade.provider_options()
        self._io.write_line("AI provider (none = heuristics; grok = advisory only):")
        for i, opt in enumerate(options, start=1):
            mark = "implemented" if opt.implemented else "reserved"
            self._io.write_line(f"  {i}) {opt.name}  [{mark}]")
        provider = self._ask("Provider [1]: ")
        if provider is None:
            return None
        provider = provider.strip() or "1"
        authorized_by = None
        note = None
        mode_key = mode.strip().lower()
        if mode_key in {"3", "authorized_assessment", "professional"}:
            authorized_by = self._ask_required("Authorized by: ")
            if authorized_by is None:
                return None
            note = self._ask("Authorization note (optional): ") or None
        try:
            mission = self._facade.create_mission(
                target=target,
                name=name,
                intent=intent,
                mode=mode,
                ai_provider=provider,
                authorized_by=authorized_by,
                authorization_note=note,
            )
        except Exception as exc:
            self._io.write_line(operator_message(exc))
            retry = self._ask("Try again? [y/N]: ")
            if retry and retry.strip().lower().startswith("y"):
                return self._wizard()
            return None
        if mission.ai_provider == "grok":
            ai = self._facade.get_ai_status()
            if ai.status == "AVAILABLE":
                self._io.write_line(
                    "Grok is advisory only. Deterministic Brain remains the planner."
                )
            else:
                self._io.write_line(
                    f"Grok selected. AI {ai.status.lower()}: {ai.reason}. "
                    "Deterministic Brain will plan."
                )
        elif mission.ai_provider != "none":
            self._io.write_line(
                f"Recorded provider '{mission.ai_provider}'. "
                "Not implemented in v1; deterministic Brain will plan."
            )
        return self._confirm_scope(mission.mission_id)

    def _confirm_scope(self, mission_id: str) -> str | None:
        while True:
            status = self._facade.get_mission_status(mission_id)
            self._io.write_line()
            self._io.write_line(render_scope(status.scope, self._io.color))
            answer = self._ask("Confirm this scope? [y]es / [e]dit / [n]o: ")
            if answer is None:
                return None
            token = answer.strip().lower()
            if token in {"y", "yes"}:
                try:
                    confirmed = self._facade.confirm_mission(mission_id)
                except Exception as exc:
                    self._io.write_line(operator_message(exc))
                    return None
                self._io.write_line(f"Mission {confirmed.status.value}. Scope is frozen.")
                return mission_id
            if token in {"n", "no"}:
                self._io.write_line("Confirmation cancelled.")
                return None
            if token in {"e", "edit"}:
                self._edit_scope(mission_id)
                continue
            self._io.write_line("Please answer y, e, or n.")

    def _edit_scope(self, mission_id: str) -> None:
        raw = self._ask("Additional excluded targets (comma-separated, empty skips): ")
        if not raw:
            return
        extras = [part.strip() for part in raw.split(",") if part.strip()]
        if not extras:
            return
        try:
            status = self._facade.get_mission_status(mission_id)
            merged = list(status.scope.excluded_targets) + extras
            self._facade.update_scope(mission_id, excluded_targets=merged)
        except Exception as exc:
            self._io.write_line(operator_message(exc))

    def _dashboard_loop(self, mission_id: str) -> int:
        self._auto = False
        while True:
            try:
                dash = self._facade.get_dashboard(mission_id)
            except Exception as exc:
                self._io.write_line(operator_message(exc))
                return 1
            self._io.clear()
            self._io.write(render_dashboard(dash, color=self._io.color))
            if self._auto and dash.mission.status == "RUNNING":
                pending = self._io.poll_key()
                if pending:
                    if self._handle_key(mission_id, pending, dash):
                        return 0
                    continue
                try:
                    cycle = self._facade.run_one_cycle(mission_id)
                except Exception as exc:
                    self._io.write_line(operator_message(exc))
                    self._auto = False
                    continue
                if cycle.completed or cycle.paused:
                    self._auto = False
                continue
            key = self._io.read_key("command> ")
            if key is None:
                return 0
            if self._handle_key(mission_id, key, dash):
                return 0

    def _handle_key(self, mission_id: str, key: str, dash: DashboardView) -> bool:
        action = BINDINGS.get(key.strip().lower())
        if action is None:
            if key.strip():
                self._io.write_line(f"Unknown command '{key}'.")
                self._pause_msg()
            return False
        try:
            return self._dispatch(action, mission_id, dash)
        except Exception as exc:
            self._io.write_line(operator_message(exc))
            self._pause_msg()
            self._auto = False
            return False

    def _dispatch(self, action: str, mission_id: str, dash: DashboardView) -> bool:
        if action == "quit":
            if dash.mission.status == "RUNNING":
                self._facade.pause_mission(mission_id)
                self._io.write_line("Paused before quit.")
            self._io.write_line("Goodbye.")
            return True
        if action == "start":
            status = dash.mission.status
            if status == "CONFIRMED":
                self._facade.start_mission(mission_id)
            elif status == "PAUSED":
                self._facade.resume_mission(mission_id)
            elif status != "RUNNING":
                self._io.write_line(f"Cannot start from {status}.")
                self._pause_msg()
                return False
            self._auto = True
            return False
        if action == "pause":
            self._facade.pause_mission(mission_id)
            self._auto = False
            return False
        if action == "resume":
            self._facade.resume_mission(mission_id)
            self._auto = True
            return False
        if action == "stop":
            confirm = self._ask("Stop mission? [y/N]: ")
            if confirm and confirm.strip().lower().startswith("y"):
                self._facade.stop_mission(mission_id)
                self._auto = False
            return False
        if action == "cycle":
            if dash.mission.status == "CONFIRMED":
                self._facade.start_mission(mission_id)
            self._facade.run_one_cycle(mission_id)
            return False
        if action == "findings":
            self._page(render_findings(self._facade.get_findings(mission_id), self._io.color))
            return False
        if action == "investigations":
            self._page(
                render_investigations(self._facade.get_investigations(mission_id), self._io.color)
            )
            return False
        if action == "world":
            self._page(render_world(self._facade.get_world_summary(mission_id), self._io.color))
            return False
        if action == "graph":
            self._page(render_graph(self._facade.get_graph(mission_id), self._io.color))
            return False
        if action == "network":
            self._page(render_network(self._facade.get_network(mission_id), self._io.color))
            return False
        if action == "target":
            net = self._facade.get_network(mission_id)
            self._io.write_line()
            self._io.write(render_network(net, self._io.color))
            self._io.write_line(f"TARGET CHANGED?\nOld: {net.current_locator or net.target or '-'}")
            raw = self._ask("New locator (empty cancels): ")
            if not raw or not raw.strip():
                return False
            try:
                updated = self._facade.confirm_locator(mission_id, raw.strip())
            except Exception as exc:
                self._io.write_line(operator_message(exc))
                self._pause_msg()
                return False
            self._io.write_line(
                f"Confirmed {updated.current_locator}. History preserved. Scope unchanged."
            )
            self._pause_msg()
            return False
        if action == "hypotheses":
            self._page(render_hypotheses(self._facade.get_hypotheses(mission_id), self._io.color))
            return False
        if action == "logs":
            events = self._facade.get_recent_events(mission_id, limit=20)
            self._page(render_logs(events, self._io.color))
            return False
        if action == "report":
            try:
                json_path, md_path = self._facade.export_report(mission_id)
            except Exception as exc:
                self._io.write_line(operator_message(exc))
                self._pause_msg()
                return False
            self._io.write_line(f"Wrote {json_path}")
            self._io.write_line(f"Wrote {md_path}")
            self._pause_msg()
            return False
        if action == "help":
            self._page(HELP_TEXT + "\n")
            return False
        return False

    def _page(self, text: str) -> None:
        self._io.write_line()
        self._io.write(text)
        self._pause_msg()

    def _pause_msg(self) -> None:
        self._ask("Enter to continue: ")

    def _ask(self, prompt: str) -> str | None:
        return self._io.read_line(prompt)

    def _ask_required(self, prompt: str) -> str | None:
        while True:
            value = self._io.read_line(prompt)
            if value is None:
                return None
            if value.strip():
                return value.strip()
            self._io.write_line("A value is required.")


def render_status_line(view: DashboardView, color: bool = False) -> str:
    return render_mission_header(view.mission, color)
