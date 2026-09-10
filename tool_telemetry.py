#!/usr/bin/env python3
"""Privacy-preserving seven-day telemetry for local developer tools.

The collector records aggregates only.  It deliberately never stores shell
commands, tool arguments, prompts, JSONL payloads, session paths, or probe
output.  This makes it suitable for deciding which locally-installed tools are
useful without turning the state directory into another conversation archive.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import resource
import shutil
import sqlite3
import stat
import subprocess
import shlex
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


APP_NAME = "tool-telemetry"
EVENTS_FILE = "events.jsonl"
STATE_FILE = "state.json"
LOCK_FILE = ".lock"
DEEP_INTERVAL_SECONDS = 6 * 60 * 60
SAMPLE_INTERVAL_SECONDS = 5 * 60
WINDOW_SECONDS = 168 * 60 * 60
EXPECTED_SAMPLES = WINDOW_SECONDS // SAMPLE_INTERVAL_SECONDS
MIN_DECISIVE_COVERAGE_PERCENT = 90.0
MIN_DECISIVE_DURATION_SECONDS = int(6.5 * 24 * 60 * 60)
MIN_ACTIVE_DAYS = 3
MIN_NEW_SESSION_EVENTS = 20
USAGE_PARSER_VERSION = 2
PROCESS_MATCHER_VERSION = 2
OUTCOME_ATTRIBUTION_VERSION = 2
LATENCY_BUCKETS_MS = (10, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000)
JSONL_SUFFIX = ".jsonl"
MAX_JSONL_FILES = 20_000


@dataclass(frozen=True)
class Tool:
    key: str
    label: str
    commands: tuple[str, ...]
    process_tokens: tuple[str, ...]
    signals: tuple[tuple[str, str], ...] = ()
    probe: tuple[str, ...] = ()
    cli_commands: tuple[str, ...] | None = None
    probe_timeout_seconds: float = 4.0
    process_entrypoints: tuple[str, ...] = ()
    process_path_roots: tuple[str, ...] = ()
    process_modules: tuple[str, ...] = ()
    require_direct_realpath: bool = False


# This is the complete, fixed scope from the 2026-09-01 tool audit.  Additions
# need an explicit audit decision; unknown executables/events are ignored.
TOOLS: tuple[Tool, ...] = (
    Tool("segundocerebro", "SegundoCerebro (sc/sc_code)", ("sc",), ("sc", "sc_code"), (("workspace", ".segundocerebro/workspace.json"),), ("sc", "--help"), probe_timeout_seconds=20.0, process_entrypoints=("http_server", "watcher_daemon", "run_turn_processor", "mcp_server_v2", "mcp_proxy", "sc-code"), process_path_roots=("/segundocerebro/",)),
    Tool("codeweb", "codeweb", ("codeweb",), ("codeweb",), (("unsupported", ".codeweb/unsupported.json"),), (), cli_commands=(), process_entrypoints=("codeweb-mcp", "mcp-server"), process_path_roots=("/plugins/cache/codeweb/", "/node_modules/.bin/codeweb-mcp")),
    Tool("graphify", "Graphify", ("graphify",), ("graphify",), (("graph", "graphify-out/GRAPH_REPORT.md"),), ("graphify", "--version")),
    Tool("gitnexus", "GitNexus", ("gitnexus",), ("gitnexus",), (), ("gitnexus", "--version")),
    Tool("ast_grep", "ast-grep (sg)", ("ast-grep", "sg"), ("ast-grep", "sg"), (), ("ast-grep", "--version"), require_direct_realpath=True),
    Tool("semgrep", "Semgrep", ("semgrep",), ("semgrep",), (), ("semgrep", "--version", "--disable-version-check"), probe_timeout_seconds=20.0),
    Tool("ripgrep", "ripgrep", ("rg", "ripgrep"), ("ripgrep", "rg"), (), ("rg", "--version"), require_direct_realpath=True),
    Tool("h5i", "h5i", ("h5i",), ("h5i",), (), ("h5i", "--version")),
    Tool("context_mode", "context-mode", ("context-mode",), ("context-mode",), (), ("context-mode", "--version"), process_entrypoints=("start",), process_path_roots=("/plugins/cache/context-mode/",)),
    Tool("claude_mem", "claude-mem", ("claude-mem",), ("claude-mem", "chroma-mcp"), (), ("claude-mem", "--version"), process_entrypoints=("worker-service", "mcp-server", "chroma-mcp"), process_path_roots=("/claude-mem/", "/chroma/")),
    Tool("repomix", "Repomix", ("repomix",), ("repomix",), (), ("repomix", "--version")),
    Tool("ktx", "KTX", ("ktx",), ("ktx",), (("project", "ktx.yaml"),), ("ktx", "--version"), probe_timeout_seconds=20.0),
    Tool("squad", "Squad", ("squad",), ("squad",), (("state", ".squad"),), ("squad", "--version")),
    Tool("headroom", "Headroom", ("headroom",), ("headroom",), (), ("headroom", "--version"), probe_timeout_seconds=20.0, process_entrypoints=("headroom",), process_path_roots=("/.local/bin/headroom", "/headroom/"), process_modules=("headroom.cli",)),
    Tool("doppelbrain", "DoppelBrain", ("doppelbrain", "dbrain-mcp-proxy"), ("doppelbrain", "dbrain-mcp-proxy"), (), ("dbrain-mcp-proxy", "--help"), cli_commands=("dbrain-mcp-proxy",)),
    Tool("cmem", "cmem", ("cmem",), ("cmem",), (), ("cmem", "--version")),
    Tool("codex_security", "codex-security", ("codex-security",), ("codex-security",), (), ("codex-security", "--version"), process_entrypoints=("server",), process_path_roots=("/codex-security/",)),
    Tool("codex_tui", "codex-tui", ("codex",), ("codex",), (), ("codex", "--version")),
    Tool("codebase_memory_mcp", "codebase-memory-mcp", ("codebase-memory-mcp",), ("codebase-memory",), (), ("codebase-memory-mcp", "--version")),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def default_state_dir() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / APP_NAME


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def secure_file(path: Path) -> None:
    path.chmod(0o600)


class TelemetryLock:
    """Advisory lock; keeps sample/init/finalize writes serialised."""

    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / LOCK_FILE
        self.handle: Any | None = None

    def __enter__(self) -> "TelemetryLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        self.handle = open(self.path, "a+", encoding="utf-8")
        secure_file(self.path)
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.handle.close()
            raise RuntimeError("coletor já está em execução") from exc
        return self

    def __exit__(self, *_: Any) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


class WindowExpired(RuntimeError):
    """Raised before any collection work after the fixed seven-day window."""


def paths(state_dir: Path) -> tuple[Path, Path]:
    return state_dir / EVENTS_FILE, state_dir / STATE_FILE


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary_name, path)
        secure_file(path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
        secure_file(path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def load_state(state_dir: Path) -> dict[str, Any]:
    _, state_path = paths(state_dir)
    if not state_path.exists():
        return {}
    try:
        with state_path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"estado inválido: {state_path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"estado inválido: {state_path}")
    return value


def append_event(state_dir: Path, event: Mapping[str, Any]) -> None:
    event_path, _ = paths(state_dir)
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(event_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, encoded)
    finally:
        os.close(fd)


def history_path_from_env() -> Path:
    return Path(os.environ.get("HISTFILE", Path.home() / ".zsh_history")).expanduser()


def cursor_for(path: Path) -> dict[str, int]:
    info = path.stat()
    return {"inode": int(info.st_ino), "offset": int(info.st_size)}


def path_fingerprint(path: Path) -> str:
    """Stable cursor key; never persist a session path."""
    return hashlib.sha256(os.fsencode(str(path))).hexdigest()


def discover_jsonl(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    discovered: list[Path] = []
    try:
        for candidate in root.rglob(f"*{JSONL_SUFFIX}"):
            if candidate.is_file():
                discovered.append(candidate)
                if len(discovered) >= MAX_JSONL_FILES:
                    break
    except OSError:
        return discovered
    return sorted(discovered)


def empty_state(history_path: Path, event_roots: Mapping[str, Path]) -> dict[str, Any]:
    window_start = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    state: dict[str, Any] = {
        "schema": 1,
        "run_id": str(uuid.uuid4()),
        "window_start": window_start.isoformat(),
        "window_end": (window_start + dt.timedelta(hours=168)).isoformat(),
        "history_cursor": cursor_for(history_path) if history_path.exists() else {"inode": 0, "offset": 0},
        "event_cursors": {},
    }
    for origin, root in event_roots.items():
        state["event_cursors"][origin] = {
            path_fingerprint(file): cursor_for(file) for file in discover_jsonl(root)
        }
    return state


def initialise(
    state_dir: Path,
    history_path: Path | None = None,
    event_roots: Mapping[str, Path] | None = None,
    *,
    new_run: bool = False,
) -> dict[str, Any]:
    history_path = history_path or history_path_from_env()
    event_roots = event_roots or default_event_roots()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    event_path, state_path = paths(state_dir)
    if state_path.exists() and not new_run:
        return load_state(state_dir)
    state = empty_state(history_path, event_roots)
    write_json_atomic(state_path, state)
    append_event(state_dir, {
        "at": utc_now(), "kind": "initialised", "run_id": state["run_id"],
        "window_start": state["window_start"], "window_end": state["window_end"], "tool_count": len(TOOLS),
    })
    secure_file(event_path)
    return state


def default_event_roots() -> dict[str, Path]:
    return {
        "codex_jsonl": Path.home() / ".codex" / "sessions",
        "claude_jsonl": Path.home() / ".claude" / "projects",
    }


def heredoc_openings(line: str) -> list[tuple[str, bool]]:
    """Return shell heredoc delimiters found outside quotes and comments."""
    openings: list[tuple[str, bool]] = []
    index = 0
    quote: str | None = None
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        if not line.startswith("<<", index) or line.startswith("<<<", index):
            index += 1
            continue
        index += 2
        strip_tabs = index < len(line) and line[index] == "-"
        if strip_tabs:
            index += 1
        while index < len(line) and line[index] in " \t":
            index += 1
        delimiter_quote = line[index] if index < len(line) and line[index] in {"'", '"'} else None
        if delimiter_quote:
            index += 1
        delimiter: list[str] = []
        while index < len(line):
            char = line[index]
            if delimiter_quote and char == delimiter_quote:
                index += 1
                break
            if not delimiter_quote and (char.isspace() or char in ";|&<>()"):
                break
            if char == "\\" and index + 1 < len(line):
                index += 1
                char = line[index]
            delimiter.append(char)
            index += 1
        if delimiter:
            openings.append(("".join(delimiter), strip_tabs))
    return openings


def without_heredoc_bodies(command: str) -> str:
    """Keep executable shell lines while discarding non-executed heredoc data."""
    pending: list[tuple[str, bool]] = []
    executable_lines: list[str] = []
    for line in command.splitlines(keepends=True):
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                pending.pop(0)
            continue
        executable_lines.append(line)
        pending.extend(heredoc_openings(line))
    return "".join(executable_lines)


def shell_usage_keys(command: str, command_index: Mapping[str, str]) -> set[str]:
    """Extract whitelisted executable names only; input is discarded immediately."""
    found: set[str] = set()
    for segment in re.split(r"(?:&&|\|\||\||;|\n)", without_heredoc_bodies(command)):
        tokens = re.findall(r"(?:(?:\\.)|[^\s])+", segment.strip())
        executable_seen = False
        delegated_command = False
        for token in tokens:
            if token == "--":
                delegated_command = True
                continue
            name = Path(token).name.lower()
            if name.startswith("-") or ("=" in name and not name.startswith("=")):
                continue
            if name in {"command", "env", "sudo", "time", "nice", "nohup", "npx", "pnpx", "pnpm", "bunx", "uvx", "exec"}:
                continue
            key = command_index.get(name)
            if not executable_seen:
                executable_seen = True
                if key:
                    found.add(key)
            elif delegated_command and key:
                found.add(key)
    return found


def argv_usage_keys(argv: Sequence[str], command_index: Mapping[str, str]) -> set[str]:
    """Interpret one completed argv without treating ordinary arguments as commands."""
    values = [value for value in argv if isinstance(value, str)]
    if not values:
        return set()
    executable = Path(values[0]).name.lower()
    if executable in {"sh", "bash", "zsh", "dash", "fish"}:
        for position, option in enumerate(values[1:-1], start=1):
            if option.startswith("-") and "c" in option[1:]:
                return shell_usage_keys(values[position + 1], command_index)
        return set()
    found: set[str] = set()
    executable_seen = False
    delegated_command = False
    for token in values:
        if token == "--":
            delegated_command = True
            continue
        name = Path(token).name.lower()
        if name.startswith("-") or ("=" in name and not name.startswith("=")):
            continue
        if name in {"command", "env", "sudo", "time", "nice", "nohup", "npx", "pnpx", "pnpm", "bunx", "uvx", "exec"}:
            continue
        key = command_index.get(name)
        if not executable_seen:
            executable_seen = True
            if key:
                found.add(key)
        elif delegated_command and key:
            found.add(key)
    return found


def is_h5i_capture(command: object, depth: int = 0) -> bool:
    """Identify capture invocation syntax, never infer failure cause from output."""
    if depth > 8:
        return False
    if isinstance(command, str):
        try:
            lexer = shlex.shlex(without_heredoc_bodies(command), posix=True, punctuation_chars=";&|()")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            return False
        segments: list[list[str]] = [[]]
        for token in tokens:
            if token and all(char in ";&|()" for char in token):
                segments.append([])
            else:
                segments[-1].append(token)
        return any(is_h5i_capture(segment, depth + 1) for segment in segments if segment)
    if not isinstance(command, (list, tuple)) or not all(isinstance(token, str) for token in command):
        return False
    tokens = list(command)
    while tokens and ("=" in tokens[0] or tokens[0] in {"env", "command", "exec", "time"}):
        tokens.pop(0)
    if not tokens:
        return False
    executable = Path(tokens[0]).name
    if executable in {"sh", "bash", "zsh", "dash", "fish"}:
        for position, option in enumerate(tokens[1:-1], start=1):
            if option.startswith("-") and "c" in option[1:]:
                return is_h5i_capture(tokens[position + 1], depth + 1)
        return False
    return (executable == "h5i" and tokens[1:3] == ["capture", "run"]
            and "--" in tokens[3:] and tokens.index("--", 3) < len(tokens) - 1)


def command_index(tools: Iterable[Tool]) -> dict[str, str]:
    return {command.lower(): tool.key for tool in tools for command in tool.commands}


def history_command(line: bytes) -> str:
    text = line.decode("utf-8", errors="replace").strip()
    if text.startswith(": ") and ";" in text:
        return text.split(";", 1)[1]
    return text


def count_history_usage(history_path: Path, cursor: Mapping[str, Any], index: Mapping[str, str]) -> tuple[dict[str, int], dict[str, int]]:
    if not history_path.exists():
        return {}, {"inode": 0, "offset": 0}
    info = history_path.stat()
    old_offset = int(cursor.get("offset", 0))
    same_file = int(cursor.get("inode", 0)) == int(info.st_ino)
    offset = old_offset if same_file and old_offset <= info.st_size else 0
    counts: dict[str, int] = {}
    with history_path.open("rb") as handle:
        handle.seek(offset)
        while True:
            line_start = handle.tell()
            raw_line = handle.readline()
            if not raw_line:
                break
            if not raw_line.endswith(b"\n"):
                handle.seek(line_start)
                break
            for key in shell_usage_keys(history_command(raw_line), index):
                counts[key] = counts.get(key, 0) + 1
        next_offset = handle.tell()
    return counts, {"inode": int(info.st_ino), "offset": int(next_offset)}


def tool_from_function(name: object, index: Mapping[str, str]) -> str | None:
    if not isinstance(name, str):
        return None
    normalised = name.lower().replace("_", "-")
    direct = index.get(normalised)
    if direct:
        return direct
    fragments = {
        "sc-code": "segundocerebro", "segundocerebro": "segundocerebro",
        "codeweb": "codeweb", "graphify": "graphify", "gitnexus": "gitnexus",
        "ast-grep": "ast_grep", "semgrep": "semgrep", "ripgrep": "ripgrep",
        "context-mode": "context_mode", "claude-mem": "claude_mem", "repomix": "repomix",
        "headroom": "headroom", "doppelbrain": "doppelbrain", "cmem": "cmem",
        "codex-security": "codex_security", "codex-tui": "codex_tui",
        "codebase-memory": "codebase_memory_mcp", "h5i": "h5i", "squad": "squad", "ktx": "ktx",
    }
    for fragment, key in fragments.items():
        if fragment in normalised:
            return key
    if normalised in {"list-threads", "get-thread", "continue-thread", "fork-thread", "archive-thread", "rename-thread"}:
        return "codex_tui"
    return None


def decoded_arguments(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, Mapping) else {}
    return {}


MCP_CALL_PATTERN = re.compile(r"tools\.mcp__(?P<server>[a-zA-Z0-9_-]+)__")


def javascript_code_only(value: str) -> str:
    """Mask JS strings/comments so cited tool names cannot become invocations."""
    output: list[str] = []
    state = "code"
    quote = ""
    index = 0
    while index < len(value):
        char = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if state == "code":
            if char == "/" and following == "/":
                output.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                output.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if char in {"'", '"', "`"}:
                quote = char
                output.append(" ")
                state = "string"
            else:
                output.append(char)
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                output.extend((" ", " "))
                state = "code"
                index += 2
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if char == "\\":
            output.append(" ")
            if following:
                output.append("\n" if following == "\n" else " ")
                index += 2
            else:
                index += 1
            continue
        output.append("\n" if char == "\n" else " ")
        index += 1
        if char == quote:
            state = "code"
    return "".join(output)


def custom_input_usage(value: object, index: Mapping[str, str]) -> set[str]:
    """Inspect custom-call input transiently; return names, never its contents."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        command = value.get("cmd")
        if isinstance(command, str):
            found.update(shell_usage_keys(command, index))
        for nested in value.values():
            if isinstance(nested, (Mapping, list)):
                found.update(custom_input_usage(nested, index))
        return found
    if isinstance(value, list):
        for nested in value:
            found.update(custom_input_usage(nested, index))
        return found
    if not isinstance(value, str):
        return found
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, (Mapping, list)):
        return custom_input_usage(decoded, index)
    for match in MCP_CALL_PATTERN.finditer(javascript_code_only(value)):
        key = tool_from_function(f"mcp__{match.group('server')}__", index)
        if key:
            found.add(key)
    return found


def tool_call_records(item: Mapping[str, Any], index: Mapping[str, str]) -> list[dict[str, Any]]:
    """Actual calls only. Raw call IDs and input stay in memory for this read."""
    candidate: Mapping[str, Any] | None = None
    kind = item.get("type")
    if kind == "event_msg" and isinstance(item.get("payload"), Mapping):
        payload = item["payload"]
        completed_item = payload.get("item")
        if payload.get("type") == "item_completed" and isinstance(completed_item, Mapping) and completed_item.get("type") == "McpToolCall":
            server = completed_item.get("server")
            tool = completed_item.get("tool")
            key = tool_from_function(f"mcp__{server}__{tool}", index) if isinstance(server, str) and isinstance(tool, str) else None
            if not key:
                return []
            status = completed_item.get("status")
            completed_error = True if status in {"failed", "error", "cancelled"} else False if status == "completed" else None
            return [{
                "keys": {key}, "call_id": None, "attribution": "direct",
                "timestamp": event_timestamp(item, completed_item), "completed_error": completed_error,
            }]
        if payload.get("type") == "item_completed" and isinstance(completed_item, Mapping) and completed_item.get("type") == "CommandExecution":
            commands = completed_item.get("command")
            if isinstance(commands, list):
                keys = argv_usage_keys(commands, index)
            elif isinstance(commands, str):
                keys = shell_usage_keys(commands, index)
            else:
                keys = set()
            if not keys:
                return []
            status = completed_item.get("status")
            exit_code = completed_item.get("exit_code")
            completed_error: bool | None = None
            if status in {"failed", "error", "cancelled"} or (isinstance(exit_code, int) and exit_code != 0):
                completed_error = True
            elif status == "completed" or exit_code == 0:
                completed_error = False
            return [{
                "keys": keys, "call_id": None, "attribution": "direct",
                "timestamp": event_timestamp(item, completed_item), "completed_error": completed_error,
                "h5i_capture": is_h5i_capture(commands),
            }]
    if kind == "response_item" and isinstance(item.get("payload"), Mapping):
        candidate = item["payload"]
    elif kind in {"function_call", "tool_use", "custom_tool_call"}:
        candidate = item
    elif kind == "assistant" and isinstance(item.get("message"), Mapping):
        content = item["message"].get("content")
        if isinstance(content, list):
            result: list[dict[str, Any]] = []
            for block in content:
                if isinstance(block, Mapping) and block.get("type") == "tool_use":
                    enriched = dict(block)
                    if "timestamp" not in enriched and isinstance(item.get("timestamp"), (str, int, float)):
                        enriched["timestamp"] = item["timestamp"]
                    result.extend(tool_call_records(enriched, index))
            return result
    if candidate is None or candidate.get("type") not in {"function_call", "tool_use", "custom_tool_call"}:
        return []
    h5i_capture = False
    if candidate.get("type") == "custom_tool_call":
        custom_input = candidate.get("input")
        if isinstance(custom_input, str):
            try:
                decoded_custom_input = json.loads(custom_input)
            except json.JSONDecodeError:
                decoded_custom_input = None
            keys = custom_input_usage(decoded_custom_input, index) if isinstance(decoded_custom_input, (Mapping, list)) else set()
        else:
            keys = custom_input_usage(custom_input, index)
        attribution = "orchestrator"
    else:
        name = candidate.get("name")
        direct = tool_from_function(name, index)
        if direct:
            keys = {direct}
        else:
            normalised_name = name.lower().replace("_", "-") if isinstance(name, str) else ""
            if not isinstance(name, str) or normalised_name not in {"bash", "exec", "exec-command", "shell", "terminal"}:
                return []
            arguments = decoded_arguments(candidate.get("arguments", candidate.get("input", {})))
            command = arguments.get("cmd", arguments.get("command", arguments.get("script", "")))
            keys = shell_usage_keys(command, index) if isinstance(command, str) else set()
            h5i_capture = is_h5i_capture(command)
        attribution = "direct"
    name = candidate.get("name")
    raw_call_id = candidate.get("call_id", candidate.get("tool_use_id", candidate.get("id")))
    return [{
        "keys": keys, "call_id": raw_call_id if isinstance(raw_call_id, str) else None,
        "attribution": attribution, "timestamp": event_timestamp(item, candidate),
        "h5i_capture": h5i_capture,
    }] if keys else []


def function_usage(item: Mapping[str, Any], index: Mapping[str, str]) -> set[str]:
    """Compatibility view for tests and simple counters."""
    return {key for record in tool_call_records(item, index) for key in record["keys"]}


def event_timestamp(item: Mapping[str, Any], candidate: Mapping[str, Any]) -> float | None:
    for source in (candidate, item):
        for field in ("timestamp", "created_at", "time"):
            value = source.get(field)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    continue
    return None


def output_metadata(candidate: Mapping[str, Any]) -> bool:
    """Read error/exit status only; output itself never leaves this function."""
    is_error = candidate.get("is_error") is True
    exit_code: int | None = candidate.get("exit_code") if isinstance(candidate.get("exit_code"), int) else None
    output = candidate.get("output", candidate.get("content"))
    if isinstance(output, Mapping):
        if output.get("is_error") is True:
            is_error = True
        if isinstance(output.get("exit_code"), int):
            exit_code = output["exit_code"]
    elif isinstance(output, str):
        try:
            decoded = json.loads(output)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, Mapping):
            if decoded.get("is_error") is True:
                is_error = True
            if isinstance(decoded.get("exit_code"), int):
                exit_code = decoded["exit_code"]
        elif match := re.search(r"[\"']?exit_code[\"']?\s*[:=]\s*(-?\d+)", output):
            exit_code = int(match.group(1))
    return is_error or (exit_code is not None and exit_code != 0)


def tool_output_records(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Output records from Codex and Claude; custom_tool_call_output is allowed here only."""
    candidate: Mapping[str, Any] | None = None
    kind = item.get("type")
    if kind == "response_item" and isinstance(item.get("payload"), Mapping):
        candidate = item["payload"]
    elif kind in {"function_call_output", "custom_tool_call_output", "tool_result"}:
        candidate = item
    elif kind == "user" and isinstance(item.get("message"), Mapping):
        content = item["message"].get("content")
        if isinstance(content, list):
            result: list[dict[str, Any]] = []
            for block in content:
                if isinstance(block, Mapping) and block.get("type") == "tool_result":
                    enriched = dict(block)
                    if "timestamp" not in enriched and isinstance(item.get("timestamp"), (str, int, float)):
                        enriched["timestamp"] = item["timestamp"]
                    result.extend(tool_output_records(enriched))
            return result
    if candidate is None or candidate.get("type") not in {"function_call_output", "custom_tool_call_output", "tool_result"}:
        return []
    raw_call_id = candidate.get("call_id", candidate.get("tool_use_id", candidate.get("id")))
    if not isinstance(raw_call_id, str):
        return []
    return [{
        "call_id": raw_call_id,
        "is_error": output_metadata(candidate),
        "envelope": candidate.get("type") == "custom_tool_call_output",
        "timestamp": event_timestamp(item, candidate),
    }]


def empty_outcome() -> dict[str, Any]:
    return {"calls": 0, "success": 0, "error": 0, "unknown": 0, "capture_exit_zero": 0, "capture_exit_nonzero": 0, "attribution": {"direct": 0, "orchestrator": 0}, "latency_ms": {"count": 0, "sum": 0, "max": 0, "buckets": {}}}


def latency_bucket(latency_ms: int) -> str:
    for upper_bound in LATENCY_BUCKETS_MS:
        if latency_ms <= upper_bound:
            return str(upper_bound)
    return "overflow"


def add_outcome_call(outcomes: dict[str, dict[str, Any]], key: str, attribution: str) -> None:
    outcome = outcomes.setdefault(key, empty_outcome())
    outcome["calls"] += 1
    outcome["attribution"][attribution] = outcome["attribution"].get(attribution, 0) + 1


def add_outcome_result(outcomes: dict[str, dict[str, Any]], entry: Mapping[str, Any], is_error: bool, ended_at: float | None, envelope: bool) -> None:
    started_at = entry.get("timestamp")
    latency_ms = round((ended_at - started_at) * 1000) if isinstance(started_at, (int, float)) and isinstance(ended_at, (int, float)) and ended_at >= started_at else None
    for key in entry.get("keys", []):
        outcome = outcomes.setdefault(key, empty_outcome())
        if envelope and entry.get("attribution") == "orchestrator":
            outcome["unknown"] += 1
            continue
        if key == "h5i" and entry.get("h5i_capture"):
            outcome["unknown"] += 1
            outcome["capture_exit_nonzero" if is_error else "capture_exit_zero"] += 1
            continue
        # Pending calls from before this change lack reliable attribution.
        if key == "h5i" and "h5i_capture" not in entry:
            outcome["unknown"] += 1
            continue
        outcome["error" if is_error else "success"] += 1
        if latency_ms is not None:
            latency = outcome["latency_ms"]
            latency["count"] += 1
            latency["sum"] += latency_ms
            latency["max"] = max(latency["max"], latency_ms)
            bucket = latency_bucket(latency_ms)
            latency["buckets"][bucket] = latency["buckets"].get(bucket, 0) + 1


def count_jsonl_usage(
    root: Path,
    cursors: Mapping[str, Any],
    index: Mapping[str, str],
    pending_calls: Mapping[str, Any],
    excluded_fingerprints: Iterable[str] = (),
) -> tuple[dict[str, int], dict[str, Any], dict[str, dict[str, Any]], dict[str, Any], int]:
    counts: dict[str, int] = {}
    next_cursors: dict[str, Any] = dict(cursors)
    outcomes: dict[str, dict[str, Any]] = {}
    next_pending: dict[str, Any] = dict(pending_calls)
    excluded = {value for value in excluded_fingerprints if isinstance(value, str)}
    new_events = 0
    for file in discover_jsonl(root):
        fingerprint = path_fingerprint(file)
        info = file.stat()
        if fingerprint in excluded:
            next_cursors[fingerprint] = {"inode": int(info.st_ino), "offset": int(info.st_size)}
            continue
        prior = cursors.get(fingerprint, {})
        old_offset = int(prior.get("offset", 0)) if isinstance(prior, Mapping) else 0
        same_file = isinstance(prior, Mapping) and int(prior.get("inode", 0)) == int(info.st_ino)
        offset = old_offset if same_file and old_offset <= info.st_size else 0
        try:
            with file.open("rb") as handle:
                handle.seek(offset)
                while True:
                    line_start = handle.tell()
                    raw_line = handle.readline()
                    if not raw_line:
                        break
                    if not raw_line.endswith(b"\n"):
                        handle.seek(line_start)
                        break
                    try:
                        value = json.loads(raw_line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if not isinstance(value, Mapping):
                        continue
                    new_events += 1
                    for record in tool_call_records(value, index):
                        raw_call_id = record["call_id"]
                        completed_error = record.get("completed_error")
                        for key in record["keys"]:
                            counts[key] = counts.get(key, 0) + 1
                            add_outcome_call(outcomes, key, record["attribution"])
                            if isinstance(completed_error, bool):
                                if key == "h5i" and record.get("h5i_capture"):
                                    outcomes[key]["unknown"] += 1
                                    outcomes[key]["capture_exit_nonzero" if completed_error else "capture_exit_zero"] += 1
                                else:
                                    outcomes[key]["error" if completed_error else "success"] += 1
                            elif not raw_call_id:
                                outcomes[key]["unknown"] += 1
                        if raw_call_id:
                            next_pending[hashlib.sha256(raw_call_id.encode()).hexdigest()] = {
                                "keys": sorted(record["keys"]), "attribution": record["attribution"], "timestamp": record["timestamp"],
                                "h5i_capture": record.get("h5i_capture", False),
                            }
                    for output in tool_output_records(value):
                        pending_key = hashlib.sha256(output["call_id"].encode()).hexdigest()
                        entry = next_pending.pop(pending_key, None)
                        if isinstance(entry, Mapping):
                            add_outcome_result(outcomes, entry, bool(output["is_error"]), output["timestamp"], bool(output["envelope"]))
                next_offset = handle.tell()
        except OSError:
            continue
        next_cursors[fingerprint] = {"inode": int(info.st_ino), "offset": int(next_offset)}
    return counts, next_cursors, outcomes, next_pending, new_events


ProcessRow = tuple[float, int, int, str] | tuple[float, int, int, str, str]


def collect_process_rows() -> list[ProcessRow]:
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,etimes=,pcpu=,rss=,args="], check=False, capture_output=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows: list[ProcessRow] = []
    for raw in completed.stdout.splitlines():
        parts = raw.decode("utf-8", errors="replace").strip().split(None, 4)
        if len(parts) != 5:
            continue
        try:
            pid = int(parts[0])
            executable_path = os.path.realpath(os.readlink(f"/proc/{pid}/exe")).lower()
            rows.append((float(parts[2]), int(parts[3]), int(parts[1]), parts[4].lower(), executable_path))
        except ValueError:
            continue
        except OSError:
            rows.append((float(parts[2]), int(parts[3]), int(parts[1]), parts[4].lower(), ""))
    return rows


def executable_name(argument: str) -> str:
    """Return an executable or script identity, never an arbitrary argument."""
    name = Path(argument).name.lower()
    for suffix in (".py", ".mjs", ".cjs", ".js", ".ts"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def first_command_argument(arguments: Sequence[str]) -> Sequence[str]:
    """Strip simple process wrappers before resolving their launched command."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return arguments[index + 1:]
        if argument.startswith("-") or "=" in argument:
            index += 1
            continue
        return arguments[index:]
    return ()


def process_executables(arguments: Sequence[str]) -> set[str]:
    """Extract executable identities without treating interpreter scripts as binaries.

    Labels such as ``--who codex`` and earlyoom preferences are never treated as
    executable identities. A shell or process wrapper may name one launched
    executable only after its explicit command boundary.
    """
    if not arguments:
        return set()
    executable = executable_name(arguments[0])
    identities = {executable}
    remaining = arguments[1:]
    if executable == "env":
        return identities | process_executables(first_command_argument(remaining))
    if executable in {"nice", "nohup", "setsid", "timeout"}:
        return identities | process_executables(first_command_argument(remaining))
    if executable == "systemd-inhibit":
        separator = next((index for index, argument in enumerate(remaining) if argument == "--"), None)
        return identities if separator is None else identities | process_executables(remaining[separator + 1:])
    if executable in {"sh", "bash", "zsh", "fish"}:
        try:
            command_index = remaining.index("-c")
        except ValueError:
            return identities
        if len(remaining) > command_index + 1:
            try:
                return identities | process_executables(shlex.split(remaining[command_index + 1]))
            except ValueError:
                return identities
    if executable in {"pnpm", "npm", "npx", "uv"}:
        command = first_command_argument(remaining)
        if command and command[0] in {"exec", "run"}:
            command = first_command_argument(command[1:])
        if command:
            return identities | process_executables(command)
    return identities


def process_entrypoints(arguments: Sequence[str]) -> set[str]:
    """Return script/module entrypoint identities for interpreters and package runners."""
    if not arguments:
        return set()
    executable = executable_name(arguments[0])
    remaining = arguments[1:]
    if executable.startswith("python") or executable in {"node", "bun", "deno"}:
        command = first_command_argument(remaining)
        return {executable_name(command[0])} if command and command[0] not in {"-c", "-m"} else set()
    if executable in {"pnpm", "npm", "npx", "uv"}:
        command = first_command_argument(remaining)
        if command and command[0] in {"exec", "run"}:
            command = first_command_argument(command[1:])
        return {executable_name(command[0])} if command else set()
    return set()


def process_modules(arguments: Sequence[str]) -> set[str]:
    """Return exact Python modules launched with ``-m``; never prefix-match."""
    if not arguments or not executable_name(arguments[0]).startswith("python"):
        return set()
    remaining = arguments[1:]
    try:
        module_index = remaining.index("-m")
    except ValueError:
        return set()
    if module_index + 1 >= len(remaining):
        return set()
    module = remaining[module_index + 1]
    return {module.lower()} if module and not module.startswith("-") else set()


def command_arguments(command_line: str) -> list[str]:
    try:
        return shlex.split(command_line)
    except ValueError:
        return []


def row_executable_path(row: ProcessRow) -> str:
    return row[4] if len(row) == 5 else ""


def direct_executable_realpath_matches(tool: Tool, row: ProcessRow) -> bool:
    expected_paths = {
        os.path.realpath(found).lower()
        for command in tool.commands
        if (found := shutil.which(command))
    }
    return bool(expected_paths) and row_executable_path(row) in expected_paths


def process_matches(tool: Tool, row: ProcessRow) -> bool:
    arguments = command_arguments(row[3])
    executables = process_executables(arguments)
    if set(tool.process_tokens).intersection(executables):
        return not tool.require_direct_realpath or direct_executable_realpath_matches(tool, row)
    if set(tool.process_modules).intersection(process_modules(arguments)):
        return True
    entrypoints = process_entrypoints(arguments)
    command_line = row[3].lower()
    return bool(
        set(tool.process_entrypoints).intersection(entrypoints)
        and any(root.lower() in command_line for root in tool.process_path_roots)
    )


def process_metrics(tool: Tool, rows: Sequence[ProcessRow]) -> dict[str, int | float]:
    matches = [row for row in rows if process_matches(tool, row)]
    return {
        "count": len(matches),
        "cpu_percent": round(sum(row[0] for row in matches), 2),
        "rss_kib": sum(row[1] for row in matches),
        "uptime_seconds": max((row[2] for row in matches), default=0),
    }


def state_signals(tool: Tool, workspace: Path) -> dict[str, bool]:
    return {name: (workspace / relative).exists() for name, relative in tool.signals}


def probe(tool: Tool) -> dict[str, Any]:
    if not tool.probe or not shutil.which(tool.probe[0]):
        return {"available": False, "attempted": False}
    started = time.monotonic()
    probe_environment = None
    if tool.key == "semgrep":
        probe_environment = os.environ.copy()
        semgrep_temporary_dir = Path(tempfile.gettempdir()) / "tool-telemetry-semgrep"
        semgrep_temporary_dir.mkdir(mode=0o700, exist_ok=True)
        probe_environment["SEMGREP_SETTINGS_FILE"] = str(semgrep_temporary_dir / "settings.yml")
        probe_environment["SEMGREP_LOG_FILE"] = str(semgrep_temporary_dir / "semgrep.log")
        probe_environment["SEMGREP_SEND_METRICS"] = "off"
    try:
        completed = subprocess.run(
            tool.probe,
            check=False,
            capture_output=True,
            timeout=tool.probe_timeout_seconds,
            env=probe_environment,
        )
        timed_out = False
        output = completed.stdout + completed.stderr
        exit_code: int | None = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        output = (exc.stdout or b"") + (exc.stderr or b"")
        exit_code = None
    except OSError:
        return {"available": True, "attempted": True, "error": "launch_failed"}
    return {
        "available": True,
        "attempted": True,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_bytes": len(output),
    }


def headroom_stats(previous: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Read only two safe Headroom counters; never retain report/model/path data."""
    if not shutil.which("headroom"):
        return {"status": "unavailable"}, None
    try:
        completed = subprocess.run(
            ["headroom", "savings", "--json", "--days", "1"], check=False, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable"}, None
    if completed.returncode != 0:
        return {"status": "unavailable"}, None
    try:
        report = json.loads(completed.stdout)
        lifetime = report.get("lifetime", {}) if isinstance(report, Mapping) else {}
        calls = lifetime.get("calls") if isinstance(lifetime, Mapping) else None
        cost = lifetime.get("cost_usd") if isinstance(lifetime, Mapping) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "unknown"}, None
    if not isinstance(calls, int) or not isinstance(cost, (int, float)):
        return {"status": "unknown"}, None
    snapshot = {"calls": calls, "cost_usd": round(float(cost), 6)}
    old_calls = previous.get("calls") if isinstance(previous.get("calls"), int) else None
    old_cost = previous.get("cost_usd") if isinstance(previous.get("cost_usd"), (int, float)) else None
    return {
        "status": "available",
        "calls_delta": calls - old_calls if old_calls is not None and calls >= old_calls else None,
        "cost_usd_delta": round(float(cost) - float(old_cost), 6) if old_cost is not None and cost >= old_cost else None,
    }, snapshot


def claude_mem_signal(rows: Sequence[tuple[float, int, int, str]]) -> dict[str, Any]:
    """Presence only; configuration bytes are read transiently and discarded."""
    hook = Path.home() / ".claude" / "hooks" / "claude-mem-staleness-guard.sh"
    settings = Path.home() / ".claude" / "settings.json"
    hook_status = "present" if hook.is_file() else "absent"
    try:
        configured = b"claude-mem" in settings.read_bytes()[:1_000_000]
        config_status = "present" if configured else "absent"
    except OSError:
        config_status = "unavailable"
    process_count = sum(1 for row in rows if "claude-mem" in row[3] or "chroma" in row[3])
    return {
        "hook": hook_status,
        "configuration": config_status,
        "process_presence": "observed" if process_count else "unknown",
        "process_count": process_count,
    }


CLAUDE_MEM_TABLES = ("observations", "session_summaries", "user_prompts", "sdk_sessions")


def claude_mem_db_stats(previous: Mapping[str, Any], db_path: Path | None = None) -> tuple[dict[str, Any], dict[str, int] | None]:
    """Read aggregate rows through SQLite mode=ro. No prompt/session data crosses this boundary."""
    db_path = db_path or (Path.home() / ".claude-mem" / "claude-mem.db")
    if not db_path.is_file():
        return {"status": "unavailable"}, None
    try:
        connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=1.0)
        try:
            connection.execute("PRAGMA query_only=ON")
            snapshot = {table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in CLAUDE_MEM_TABLES}
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return {"status": "unknown"}, None
    deltas = {
        table: snapshot[table] - int(previous[table])
        for table in CLAUDE_MEM_TABLES
        if isinstance(previous.get(table), int) and snapshot[table] >= int(previous[table])
    }
    return {"status": "available", "deltas": deltas}, snapshot


def deep_due(state: Mapping[str, Any], now: dt.datetime) -> bool:
    previous = state.get("last_deep_at")
    if not isinstance(previous, str):
        return True
    try:
        then = dt.datetime.fromisoformat(previous)
    except ValueError:
        return True
    return (now - then).total_seconds() >= DEEP_INTERVAL_SECONDS


def window_expired(state: Mapping[str, Any], now: dt.datetime) -> bool:
    end = state.get("window_end")
    if not isinstance(end, str):
        return False
    try:
        return now >= dt.datetime.fromisoformat(end)
    except ValueError:
        raise RuntimeError("janela de execução inválida") from None


def merge_counts(target: dict[str, dict[str, int]], origin: str, counts: Mapping[str, int]) -> None:
    for key, count in counts.items():
        target.setdefault(key, {})[origin] = target.setdefault(key, {}).get(origin, 0) + int(count)


def collect_sample(
    state_dir: Path,
    *,
    workspace: Path | None = None,
    history_path: Path | None = None,
    event_roots: Mapping[str, Path] | None = None,
    tools: Sequence[Tool] = TOOLS,
    force_deep: bool = False,
) -> dict[str, Any]:
    collector_started = time.monotonic()
    self_before = resource.getrusage(resource.RUSAGE_SELF)
    children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    workspace = workspace or Path.cwd()
    history_path = history_path or history_path_from_env()
    event_roots = event_roots or default_event_roots()
    state = initialise(state_dir, history_path, event_roots)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if window_expired(state, now):
        raise WindowExpired("janela de 168 horas encerrada")
    index = command_index(tools)
    history_counts, history_cursor = count_history_usage(history_path, state.get("history_cursor", {}), index)
    user_usage: dict[str, dict[str, int]] = {}
    outcomes: dict[str, dict[str, Any]] = {}
    source_activity: dict[str, int] = {}
    merge_counts(user_usage, "zsh_history", history_counts)
    event_cursors = state.setdefault("event_cursors", {})
    pending_by_origin = state.setdefault("pending_calls", {})
    excluded_fingerprints = state.get("excluded_event_fingerprints", [])
    for origin, root in event_roots.items():
        counts, updated, source_outcomes, source_pending, new_events = count_jsonl_usage(
            root, event_cursors.get(origin, {}), index, pending_by_origin.get(origin, {}), excluded_fingerprints,
        )
        event_cursors[origin] = updated
        pending_by_origin[origin] = source_pending
        source_activity[origin] = new_events
        merge_counts(user_usage, origin, counts)
        for key, source_outcome in source_outcomes.items():
            target = outcomes.setdefault(key, empty_outcome())
            for field in ("calls", "success", "error", "unknown", "capture_exit_zero", "capture_exit_nonzero"):
                target[field] += source_outcome[field]
            for attribution, count in source_outcome["attribution"].items():
                target["attribution"][attribution] = target["attribution"].get(attribution, 0) + count
            for field in ("count", "sum"):
                target["latency_ms"][field] += source_outcome["latency_ms"][field]
            target["latency_ms"]["max"] = max(target["latency_ms"]["max"], source_outcome["latency_ms"]["max"])
            for bucket, count in source_outcome["latency_ms"]["buckets"].items():
                target["latency_ms"]["buckets"][bucket] = target["latency_ms"]["buckets"].get(bucket, 0) + count
    include_deep = force_deep or deep_due(state, now)
    rows = collect_process_rows()
    local_observability: dict[str, Any] = {"claude_mem": claude_mem_signal(rows)}
    if include_deep:
        headroom_observation, headroom_snapshot = headroom_stats(state.get("headroom_snapshot", {}))
        local_observability["headroom"] = headroom_observation
        if headroom_snapshot is not None:
            state["headroom_snapshot"] = headroom_snapshot
        claude_mem_observation, claude_mem_snapshot = claude_mem_db_stats(state.get("claude_mem_snapshot", {}))
        local_observability["claude_mem"]["automatic_activity"] = claude_mem_observation
        if claude_mem_snapshot is not None:
            state["claude_mem_snapshot"] = claude_mem_snapshot
    else:
        local_observability["headroom"] = {"status": "not_due"}
        local_observability["claude_mem"]["automatic_activity"] = {"status": "not_due"}
    tools_event: dict[str, Any] = {}
    probe_usage: dict[str, int] = {}
    for tool in tools:
        details: dict[str, Any] = {
            "cli_present": any(shutil.which(command) is not None for command in (tool.commands if tool.cli_commands is None else tool.cli_commands)),
            "process": process_metrics(tool, rows),
            "signals": state_signals(tool, workspace),
            "user_usage": user_usage.get(tool.key, {}),
        }
        if include_deep:
            details["probe"] = probe(tool)
            if details["probe"].get("attempted"):
                probe_usage[tool.key] = 1
        tools_event[tool.key] = details
    state["history_cursor"] = history_cursor
    state["last_sample_at"] = now.isoformat()
    if include_deep:
        state["last_deep_at"] = now.isoformat()
    write_json_atomic(paths(state_dir)[1], state)
    self_after = resource.getrusage(resource.RUSAGE_SELF)
    children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    collector_cpu_seconds = (
        self_after.ru_utime - self_before.ru_utime
        + self_after.ru_stime - self_before.ru_stime
        + children_after.ru_utime - children_before.ru_utime
        + children_after.ru_stime - children_before.ru_stime
    )
    event = {
        "at": now.isoformat(), "kind": "sample", "run_id": state["run_id"], "deep": include_deep,
        "usage_parser_version": USAGE_PARSER_VERSION,
        "outcome_attribution_version": OUTCOME_ATTRIBUTION_VERSION,
        "process_matcher_version": PROCESS_MATCHER_VERSION,
        "tools": tools_event, "outcomes": outcomes, "probe_usage": probe_usage,
        "source_activity": source_activity, "local_observability": local_observability,
        "collector": {
            "duration_ms": round((time.monotonic() - collector_started) * 1000),
            "cpu_ms": round(collector_cpu_seconds * 1000),
            "max_rss_kib": max(int(self_after.ru_maxrss), int(children_after.ru_maxrss)),
        },
    }
    append_event(state_dir, event)
    return event


def read_events(state_dir: Path) -> list[dict[str, Any]]:
    event_path, _ = paths(state_dir)
    if not event_path.exists():
        return []
    events: list[dict[str, Any]] = []
    with event_path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
    return events


def markdown_report(state_dir: Path, tools: Sequence[Tool] = TOOLS) -> str:
    state = load_state(state_dir) if paths(state_dir)[1].exists() else {}
    run_id = state.get("run_id")
    samples = [
        event for event in read_events(state_dir)
        if event.get("kind") == "sample" and event.get("run_id") == run_id
    ]
    usage_samples = [sample for sample in samples if sample.get("usage_parser_version") == USAGE_PARSER_VERSION]
    excluded_bootstrap_samples = len(samples) - len(usage_samples)
    process_samples = [sample for sample in samples if sample.get("process_matcher_version") == PROCESS_MATCHER_VERSION]
    excluded_legacy_process_samples = len(samples) - len(process_samples)
    user_totals: dict[str, int] = {tool.key: 0 for tool in tools}
    origins: dict[str, set[str]] = {tool.key: set() for tool in tools}
    probe_totals: dict[str, int] = {tool.key: 0 for tool in tools}
    observed = {tool.key: 0 for tool in tools}
    process_observed = {tool.key: 0 for tool in tools}
    cli_seen = {tool.key: False for tool in tools}
    cpu_total = {tool.key: 0.0 for tool in tools}
    cpu_peak = {tool.key: 0.0 for tool in tools}
    rss_total = {tool.key: 0 for tool in tools}
    rss_peak = {tool.key: 0 for tool in tools}
    probe_success = {tool.key: 0 for tool in tools}
    probe_error = {tool.key: 0 for tool in tools}
    probe_timeout = {tool.key: 0 for tool in tools}
    probe_latency_total = {tool.key: 0 for tool in tools}
    probe_latency_count = {tool.key: 0 for tool in tools}
    capture_exit_zero = 0
    capture_exit_nonzero = 0
    legacy_h5i_errors = 0
    runtime_calls = {tool.key: 0 for tool in tools}
    runtime_success = {tool.key: 0 for tool in tools}
    runtime_error = {tool.key: 0 for tool in tools}
    runtime_unknown = {tool.key: 0 for tool in tools}
    runtime_direct = {tool.key: 0 for tool in tools}
    runtime_orchestrator = {tool.key: 0 for tool in tools}
    runtime_latency_sum = {tool.key: 0 for tool in tools}
    runtime_latency_count = {tool.key: 0 for tool in tools}
    runtime_latency_max = {tool.key: 0 for tool in tools}
    runtime_latency_buckets = {tool.key: {} for tool in tools}
    new_session_events = 0
    headroom_available_samples = 0
    headroom_calls_delta = 0
    headroom_cost_delta = 0.0
    claude_mem_hook_samples = 0
    claude_mem_automatic_samples = 0
    claude_mem_automatic_deltas = {table: 0 for table in CLAUDE_MEM_TABLES}
    collector_durations: list[int] = []
    collector_cpu_total_ms = 0
    collector_rss_peak_kib = 0
    for sample in samples:
        usage_sample_valid = sample.get("usage_parser_version") == USAGE_PARSER_VERSION
        process_sample_valid = sample.get("process_matcher_version") == PROCESS_MATCHER_VERSION
        collector = sample.get("collector", {})
        if isinstance(collector, Mapping):
            duration = collector.get("duration_ms")
            cpu_ms = collector.get("cpu_ms")
            max_rss_kib = collector.get("max_rss_kib")
            if isinstance(duration, int):
                collector_durations.append(duration)
            if isinstance(cpu_ms, int):
                collector_cpu_total_ms += cpu_ms
            if isinstance(max_rss_kib, int):
                collector_rss_peak_kib = max(collector_rss_peak_kib, max_rss_kib)
        tools_data = sample.get("tools", {})
        for tool in tools:
            data = tools_data.get(tool.key, {}) if isinstance(tools_data, Mapping) else {}
            if not isinstance(data, Mapping):
                continue
            observed[tool.key] += 1
            cli_seen[tool.key] = cli_seen[tool.key] or bool(data.get("cli_present"))
            process = data.get("process", {})
            if process_sample_valid and isinstance(process, Mapping):
                process_observed[tool.key] += 1
                cpu = process.get("cpu_percent", 0)
                rss = process.get("rss_kib", 0)
                if isinstance(cpu, (int, float)):
                    cpu_total[tool.key] += float(cpu)
                    cpu_peak[tool.key] = max(cpu_peak[tool.key], float(cpu))
                if isinstance(rss, int):
                    rss_total[tool.key] += rss
                    rss_peak[tool.key] = max(rss_peak[tool.key], rss)
            usage = data.get("user_usage", {})
            if usage_sample_valid and isinstance(usage, Mapping):
                for origin, count in usage.items():
                    if isinstance(count, int):
                        user_totals[tool.key] += count
                        origins[tool.key].add(str(origin))
            probe_data = data.get("probe", {})
            if isinstance(probe_data, Mapping) and probe_data.get("attempted"):
                if probe_data.get("timed_out"):
                    probe_timeout[tool.key] += 1
                elif probe_data.get("exit_code") == 0:
                    probe_success[tool.key] += 1
                else:
                    probe_error[tool.key] += 1
                duration = probe_data.get("duration_ms")
                if isinstance(duration, int):
                    probe_latency_total[tool.key] += duration
                    probe_latency_count[tool.key] += 1
        for key, count in (sample.get("probe_usage", {}) or {}).items():
            if key in probe_totals and isinstance(count, int):
                probe_totals[key] += count
        sample_outcomes = sample.get("outcomes", {})
        if usage_sample_valid and isinstance(sample_outcomes, Mapping):
            for tool in tools:
                outcome = sample_outcomes.get(tool.key, {})
                if not isinstance(outcome, Mapping):
                    continue
                if tool.key == "h5i":
                    if sample.get("outcome_attribution_version") != OUTCOME_ATTRIBUTION_VERSION:
                        legacy_h5i_errors += outcome.get("error", 0)
                        outcome = {**outcome, "success": 0, "error": 0,
                                   "unknown": outcome.get("unknown", 0) + outcome.get("success", 0) + outcome.get("error", 0),
                                   "latency_ms": {}}
                    else:
                        capture_exit_zero += outcome.get("capture_exit_zero", 0)
                        capture_exit_nonzero += outcome.get("capture_exit_nonzero", 0)
                for field, target in (("calls", runtime_calls), ("success", runtime_success), ("error", runtime_error), ("unknown", runtime_unknown)):
                    value = outcome.get(field, 0)
                    if isinstance(value, int):
                        target[tool.key] += value
                attribution = outcome.get("attribution", {})
                if isinstance(attribution, Mapping):
                    for name, target in (("direct", runtime_direct), ("orchestrator", runtime_orchestrator)):
                        value = attribution.get(name, 0)
                        if isinstance(value, int):
                            target[tool.key] += value
                latency_data = outcome.get("latency_ms", {})
                if isinstance(latency_data, Mapping):
                    for field, target in (("sum", runtime_latency_sum), ("count", runtime_latency_count)):
                        value = latency_data.get(field, 0)
                        if isinstance(value, int):
                            target[tool.key] += value
                    maximum = latency_data.get("max", 0)
                    if isinstance(maximum, int):
                        runtime_latency_max[tool.key] = max(runtime_latency_max[tool.key], maximum)
                    buckets = latency_data.get("buckets", {})
                    if isinstance(buckets, Mapping):
                        for bucket, count in buckets.items():
                            if isinstance(bucket, str) and isinstance(count, int):
                                runtime_latency_buckets[tool.key][bucket] = runtime_latency_buckets[tool.key].get(bucket, 0) + count
        activity = sample.get("source_activity", {})
        if usage_sample_valid and isinstance(activity, Mapping):
            for origin in ("codex_jsonl", "claude_jsonl"):
                value = activity.get(origin, 0)
                if isinstance(value, int):
                    new_session_events += value
        local = sample.get("local_observability", {})
        if isinstance(local, Mapping):
            headroom = local.get("headroom", {})
            if isinstance(headroom, Mapping) and headroom.get("status") == "available":
                headroom_available_samples += 1
                if isinstance(headroom.get("calls_delta"), int):
                    headroom_calls_delta += headroom["calls_delta"]
                if isinstance(headroom.get("cost_usd_delta"), (int, float)):
                    headroom_cost_delta += float(headroom["cost_usd_delta"])
            claude_mem = local.get("claude_mem", {})
            if isinstance(claude_mem, Mapping):
                if claude_mem.get("hook") == "present":
                    claude_mem_hook_samples += 1
                automatic = claude_mem.get("automatic_activity", {})
                if isinstance(automatic, Mapping) and automatic.get("status") == "available":
                    claude_mem_automatic_samples += 1
                    deltas = automatic.get("deltas", {})
                    if isinstance(deltas, Mapping):
                        for table in CLAUDE_MEM_TABLES:
                            value = deltas.get(table, 0)
                            if isinstance(value, int):
                                claude_mem_automatic_deltas[table] += value
    start = state.get("window_start", "n/a")
    end = state.get("window_end", "n/a")
    sample_times: list[dt.datetime] = []
    for sample in samples:
        value = sample.get("at")
        if isinstance(value, str):
            try:
                sample_times.append(dt.datetime.fromisoformat(value))
            except ValueError:
                pass
    effective_seconds = int((max(sample_times) - min(sample_times)).total_seconds()) if len(sample_times) > 1 else 0
    effective_duration = str(dt.timedelta(seconds=effective_seconds))
    coverage_percent = (len(samples) / EXPECTED_SAMPLES) * 100
    usage_sample_times: list[dt.datetime] = []
    for sample in usage_samples:
        value = sample.get("at")
        if isinstance(value, str):
            try:
                usage_sample_times.append(dt.datetime.fromisoformat(value))
            except ValueError:
                pass
    usage_effective_seconds = int((max(usage_sample_times) - min(usage_sample_times)).total_seconds()) if len(usage_sample_times) > 1 else 0
    usage_effective_duration = str(dt.timedelta(seconds=usage_effective_seconds))
    usage_coverage_percent = (len(usage_samples) / EXPECTED_SAMPLES) * 100
    active_source_days: set[dt.date] = set()
    for sample in usage_samples:
        activity = sample.get("source_activity", {})
        if not isinstance(activity, Mapping) or not any(isinstance(activity.get(origin), int) and activity[origin] > 0 for origin in ("codex_jsonl", "claude_jsonl")):
            continue
        value = sample.get("at")
        if isinstance(value, str):
            try:
                active_source_days.add(dt.datetime.fromisoformat(value).date())
            except ValueError:
                pass
    active_days = len(active_source_days)
    representative_activity = active_days >= MIN_ACTIVE_DAYS and new_session_events >= MIN_NEW_SESSION_EVENTS
    decision = "INCONCLUSIVA" if (
        coverage_percent < MIN_DECISIVE_COVERAGE_PERCENT
        or effective_seconds < MIN_DECISIVE_DURATION_SECONDS
        or usage_coverage_percent < MIN_DECISIVE_COVERAGE_PERCENT
        or usage_effective_seconds < MIN_DECISIVE_DURATION_SECONDS
        or not representative_activity
    ) else "EVIDÊNCIA SUFICIENTE PARA REVISÃO CONTROLADA"
    collector_average_ms = sum(collector_durations) / len(collector_durations) if collector_durations else 0
    collector_p95_ms = 0
    if collector_durations:
        ordered_collector_durations = sorted(collector_durations)
        collector_p95_ms = ordered_collector_durations[max(0, (len(ordered_collector_durations) * 95 + 99) // 100 - 1)]
    event_path, state_path = paths(state_dir)
    event_bytes = event_path.stat().st_size if event_path.exists() else 0
    state_bytes = state_path.stat().st_size if state_path.exists() else 0
    lines = [
        "# Relatório de telemetria de ferramentas",
        "",
        f"Janela da execução: {start} a {end} (168 horas).",
        f"Cobertura: {len(samples)}/{EXPECTED_SAMPLES} amostras esperadas a cada 5 min ({coverage_percent:.2f}%). Duração efetiva observada: {effective_duration}.",
        f"Métricas de invocação válidas (parser v{USAGE_PARSER_VERSION}): {len(usage_samples)}/{EXPECTED_SAMPLES} ({usage_coverage_percent:.2f}%), duração {usage_effective_duration}; {excluded_bootstrap_samples} amostras de bootstrap excluídas.",
        f"Métricas CPU/RSS válidas (matcher de processos v{PROCESS_MATCHER_VERSION}): {len(process_samples)}/{EXPECTED_SAMPLES}; {excluded_legacy_process_samples} amostras legadas preservadas, porém excluídas do custo de processo.",
        f"Atividade representativa: {active_days}/{MIN_ACTIVE_DAYS} dias ativos; {new_session_events}/{MIN_NEW_SESSION_EVENTS} novos eventos de sessão Codex/Claude.",
        f"Decisão da execução: **{decision}**.",
        f"Observabilidade local: Headroom disponível em {headroom_available_samples} amostras profundas, delta de chamadas {headroom_calls_delta}, delta de economia estimada USD {headroom_cost_delta:.6f}; claude-mem hook presente em {claude_mem_hook_samples} amostras, atividade automática DB disponível em {claude_mem_automatic_samples}, deltas observações/resumos/prompts/sessões {claude_mem_automatic_deltas['observations']}/{claude_mem_automatic_deltas['session_summaries']}/{claude_mem_automatic_deltas['user_prompts']}/{claude_mem_automatic_deltas['sdk_sessions']}.",
        f"Sobrecarga do monitor: {len(collector_durations)} amostras medidas; duração média/p95/máxima {collector_average_ms:.0f}/{collector_p95_ms}/{max(collector_durations, default=0)} ms; CPU acumulada {collector_cpu_total_ms} ms; RSS pico {collector_rss_peak_kib} KiB; estado/eventos {state_bytes}/{event_bytes} bytes.",
        "Uso do usuário é separado de Probes automáticos.",
        f"A atividade Codex/Claude representa atividade global concorrente da máquina; {len(state.get('excluded_event_fingerprints', []))} sessões da própria auditoria são excluídas por hash, sem persistir caminhos.",
        "",
        "| Ferramenta | CLI vista | Uso do usuário | Origens | Custo observado (CPU/RSS) | Resultado dos probes | Amostras processo v2 |",
        "|---|---:|---:|---|---|---|---:|",
    ]
    for tool in tools:
        source = ", ".join(sorted(origins[tool.key])) or "—"
        sample_count = process_observed[tool.key]
        average_cpu = cpu_total[tool.key] / sample_count if sample_count else 0.0
        average_rss = rss_total[tool.key] / sample_count if sample_count else 0
        latency = probe_latency_total[tool.key] / probe_latency_count[tool.key] if probe_latency_count[tool.key] else 0
        cost = f"CPU média/pico {average_cpu:.2f}%/{cpu_peak[tool.key]:.2f}%; RSS média/pico {average_rss:.0f}/{rss_peak[tool.key]} KiB"
        runtime_p95 = "0"
        if runtime_latency_count[tool.key]:
            rank = (runtime_latency_count[tool.key] * 95 + 99) // 100
            seen = 0
            for bucket in [*(str(value) for value in LATENCY_BUCKETS_MS), "overflow"]:
                seen += runtime_latency_buckets[tool.key].get(bucket, 0)
                if seen >= rank:
                    runtime_p95 = f">{LATENCY_BUCKETS_MS[-1]}" if bucket == "overflow" else f"≤{bucket}"
                    break
        runtime_average = runtime_latency_sum[tool.key] / runtime_latency_count[tool.key] if runtime_latency_count[tool.key] else 0
        result = (
            f"runtime chamadas/sucesso/erro/desconhecido {runtime_calls[tool.key]}/{runtime_success[tool.key]}/{runtime_error[tool.key]}/{runtime_unknown[tool.key]}; "
            f"direto/orquestrador {runtime_direct[tool.key]}/{runtime_orchestrator[tool.key]}; "
            f"latência média/p95(máx da faixa)/máx {runtime_average:.0f}/{runtime_p95}/{runtime_latency_max[tool.key]} ms; "
            f"probe ok/erro/timeout {probe_success[tool.key]}/{probe_error[tool.key]}/{probe_timeout[tool.key]}; "
            f"latência probe média {latency:.0f} ms; chamados {probe_totals[tool.key]}"
        )
        if tool.key == "h5i":
            result += (f"; captura saída zero/não zero {capture_exit_zero}/{capture_exit_nonzero}"
                       f"; erros legados sem atribuição {legacy_h5i_errors}")
        lines.append(f"| {tool.label} | {'sim' if cli_seen[tool.key] else 'não'} | {user_totals[tool.key]} | {source} | {cost} | {result} | {sample_count} |")
    lines.extend([
        "",
        "Critério sugerido: reavaliar ferramenta sem uso do usuário na janela; uma probe bem-sucedida não conta como uso.",
        "Evidência só é conclusiva com cobertura e duração mínimas, além de ao menos três dias ativos e 20 novos eventos de sessão; isso evita decidir sobre uma semana ociosa.",
        "Remoção só é candidata com zero uso real, custo material observado e teste de desabilitação reversível; esta telemetria não autoriza remoção sozinha.",
        "Dados preservados: somente agregados, presença, métricas de processo e hashes/tamanho de saída de probe.",
        "CPU/RSS por padrão de processo é atribuição heurística, não medição causal por ferramenta.",
        f"As contagens indicam invocação, não benefício; amostras anteriores ao parser v{USAGE_PARSER_VERSION} são excluídas das métricas de uso e runtime. CPU/RSS de amostras anteriores ao matcher v{PROCESS_MATCHER_VERSION} também são preservados, mas não entram no custo observado.",
        "h5i capture run: a saída pertence à execução capturada; sem evidência específica, a origem da falha é indeterminada. Capturas entram em desconhecido para o h5i e em contadores separados de saída zero/não zero; não comprovam falha nem sucesso próprio. Erros legados do h5i também ficam sem atribuição, sem alterar os eventos originais.",
        "Hits, findings e tokens NÃO são coletados nesta versão e não são inferidos.",
    ])
    return "\n".join(lines) + "\n"


def status(state_dir: Path) -> dict[str, Any]:
    state = load_state(state_dir) if paths(state_dir)[1].exists() else {}
    samples = sum(event.get("kind") == "sample" and event.get("run_id") == state.get("run_id") for event in read_events(state_dir))
    is_expired = window_expired(state, dt.datetime.now(dt.timezone.utc)) if state else False
    return {
        "state_dir": str(state_dir), "run_id": state.get("run_id"), "window_start": state.get("window_start"),
        "window_end": state.get("window_end"), "expired": is_expired, "samples": samples, "expected_samples": EXPECTED_SAMPLES,
        "last_sample_at": state.get("last_sample_at"), "last_deep_at": state.get("last_deep_at"),
        "excluded_sessions": len(state.get("excluded_event_fingerprints", [])),
    }


def exclude_session(state_dir: Path, session_path: Path) -> dict[str, Any]:
    """Exclude one audit JSONL by path hash; the path itself is never persisted."""
    state = load_state(state_dir)
    if not state:
        raise RuntimeError("telemetria não inicializada")
    fingerprint = path_fingerprint(session_path.resolve())
    excluded = {value for value in state.get("excluded_event_fingerprints", []) if isinstance(value, str)}
    excluded.add(fingerprint)
    state["excluded_event_fingerprints"] = sorted(excluded)
    write_json_atomic(paths(state_dir)[1], state)
    return status(state_dir)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--history-file", type=Path, default=None, help="apenas para coleta/teste; conteúdo nunca é persistido")
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="raiz para sinais locais de estado")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_options(subparser: argparse.ArgumentParser) -> None:
        # argparse normally only accepts global flags before the subcommand.  The
        # installer and systemd units use them after it, so support both forms.
        subparser.add_argument("--state-dir", type=Path, default=argparse.SUPPRESS)
        subparser.add_argument("--history-file", type=Path, default=argparse.SUPPRESS)
        subparser.add_argument("--workspace", type=Path, default=argparse.SUPPRESS)

    init_parser = subparsers.add_parser("init")
    add_common_options(init_parser)
    sample_parser = subparsers.add_parser("sample")
    add_common_options(sample_parser)
    sample_parser.add_argument(
        "--force-deep", "--deep", dest="force_deep", action="store_true",
        help="força probes somente leitura",
    )
    report_parser = subparsers.add_parser("report")
    add_common_options(report_parser)
    status_parser = subparsers.add_parser("status")
    add_common_options(status_parser)
    exclude_parser = subparsers.add_parser("exclude-session")
    add_common_options(exclude_parser)
    exclude_parser.add_argument("--path", type=Path, required=True)
    finalize_parser = subparsers.add_parser("finalize")
    add_common_options(finalize_parser)
    finalize_parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    state_dir = args.state_dir.expanduser()
    history = args.history_file.expanduser() if args.history_file else None
    workspace = args.workspace.expanduser()
    try:
        if args.command == "init":
            with TelemetryLock(state_dir):
                initialise(state_dir, history, new_run=True)
            print(json.dumps(status(state_dir), sort_keys=True))
        elif args.command == "sample":
            with TelemetryLock(state_dir):
                event = collect_sample(state_dir, workspace=workspace, history_path=history, force_deep=args.force_deep)
            print(json.dumps({"at": event["at"], "deep": event["deep"], "tools": len(event["tools"])}, sort_keys=True))
        elif args.command == "report":
            print(markdown_report(state_dir), end="")
        elif args.command == "status":
            print(json.dumps(status(state_dir), sort_keys=True))
        elif args.command == "exclude-session":
            with TelemetryLock(state_dir):
                result = exclude_session(state_dir, args.path.expanduser())
            print(json.dumps(result, sort_keys=True))
        elif args.command == "finalize":
            with TelemetryLock(state_dir):
                report = markdown_report(state_dir)
                output = args.output or state_dir / "final-report.md"
                write_text_atomic(output, report)
                current_state = load_state(state_dir)
                if not current_state.get("finalised_at"):
                    current_state["finalised_at"] = utc_now()
                    write_json_atomic(paths(state_dir)[1], current_state)
                    append_event(state_dir, {"at": current_state["finalised_at"], "kind": "finalised", "run_id": current_state.get("run_id"), "samples": status(state_dir)["samples"]})
            print(str(output))
    except WindowExpired:
        print(json.dumps({"status": "expired", "window_end": load_state(state_dir).get("window_end")}, sort_keys=True))
        return 0
    except RuntimeError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
