import importlib.util
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("tool_telemetry.py")
SPEC = importlib.util.spec_from_file_location("tool_telemetry", MODULE_PATH)
telemetry = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = telemetry
SPEC.loader.exec_module(telemetry)


class ToolTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state_dir = self.root / "state"
        self.history = self.root / "zsh_history"
        self.codex = self.root / "codex"
        self.claude = self.root / "claude"
        self.codex.mkdir()
        self.claude.mkdir()
        self.tools = (
            telemetry.Tool("ripgrep", "ripgrep", ("rg",), ("python",), probe=(sys.executable, "-c", "print('secret-token')")),
            telemetry.Tool("segundocerebro", "SegundoCerebro", ("sc",), ("unlikely-process",)),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def event_roots(self):
        return {"codex_jsonl": self.codex, "claude_jsonl": self.claude}

    def test_init_starts_history_and_existing_jsonl_at_eof_with_private_files(self):
        self.history.write_text(": 1:0;rg should-not-count\n", encoding="utf-8")
        existing = self.codex / "old.jsonl"
        existing.write_text(json.dumps({"type": "function_call", "name": "Bash", "arguments": {"command": "rg old"}}) + "\n", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        state = telemetry.load_state(self.state_dir)
        self.assertEqual(state["history_cursor"]["offset"], self.history.stat().st_size)
        self.assertEqual(len(state["event_cursors"]["codex_jsonl"]), 1)
        self.assertEqual(stat.S_IMODE((self.state_dir / telemetry.EVENTS_FILE).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state_dir / telemetry.STATE_FILE).stat().st_mode), 0o600)
        self.assertNotIn(str(existing), json.dumps(state))

    def test_sample_counts_new_history_and_jsonl_without_storing_payload(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        with self.history.open("a", encoding="utf-8") as handle:
            handle.write(": 2:0;rg --glob '*.py' secret-argument\n")
        (self.codex / "new.jsonl").write_text(
            "\n".join((
                json.dumps({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "rg password-value"})}}),
                json.dumps({"type": "response_item", "payload": {"type": "function_call", "name": "tools/list", "arguments": "{}"}}),
            )) + "\n",
            encoding="utf-8",
        )
        (self.claude / "new.jsonl").write_text(json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "sc context user-secret"}}]}}) + "\n", encoding="utf-8")
        event = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=False)
        self.assertEqual(set(event["collector"]), {"duration_ms", "cpu_ms", "max_rss_kib"})
        self.assertGreaterEqual(event["collector"]["duration_ms"], 0)
        self.assertEqual(event["tools"]["ripgrep"]["user_usage"], {"zsh_history": 1, "codex_jsonl": 1})
        self.assertEqual(event["tools"]["segundocerebro"]["user_usage"], {"claude_jsonl": 1})
        serialised = json.dumps(event)
        self.assertNotIn("secret-argument", serialised)
        self.assertNotIn("password-value", serialised)
        self.assertNotIn("user-secret", serialised)
        second = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=False)
        self.assertEqual(second["tools"]["ripgrep"]["user_usage"], {})

    def test_deep_probe_keeps_only_metadata_and_report_separates_probe_usage(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        event = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=True)
        probe = event["tools"]["ripgrep"]["probe"]
        self.assertEqual(event["probe_usage"], {"ripgrep": 1})
        self.assertEqual(event["process_matcher_version"], telemetry.PROCESS_MATCHER_VERSION)
        self.assertIn("output_sha256", probe)
        self.assertNotIn("secret-token", json.dumps(probe))
        report = telemetry.markdown_report(self.state_dir, self.tools)
        self.assertIn("Uso do usuário", report)
        self.assertIn("Probes", report)
        self.assertIn("Custo observado", report)
        self.assertIn("Resultado dos probes", report)
        self.assertIn("1/2016", report)
        self.assertIn("Duração efetiva observada", report)
        self.assertIn("Decisão da execução: **INCONCLUSIVA**", report)
        self.assertIn("teste de desabilitação reversível", report)
        self.assertIn("atribuição heurística", report)
        self.assertIn("NÃO são coletados nesta versão", report)
        self.assertIn("Observabilidade local", report)
        self.assertIn("Sobrecarga do monitor", report)
        self.assertIn("matcher de processos v2", report)
        self.assertIn("atividade global concorrente", report)
        self.assertIn("| ripgrep |", report)

    def test_lock_rejects_parallel_writer(self):
        self.state_dir.mkdir()
        with telemetry.TelemetryLock(self.state_dir):
            with self.assertRaisesRegex(RuntimeError, "já está"):
                with telemetry.TelemetryLock(self.state_dir):
                    pass

    def test_cli_accepts_runtime_options_after_subcommand_and_finalizes_atomically(self):
        output = self.root / "docs" / "telemetria.md"
        result = telemetry.main([
            "sample", "--state-dir", str(self.state_dir), "--workspace", str(self.root), "--history-file", str(self.history), "--force-deep",
        ])
        self.assertEqual(result, 0)
        result = telemetry.main(["finalize", "--state-dir", str(self.state_dir), "--output", str(output)])
        self.assertEqual(result, 0)
        self.assertTrue(output.exists())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_function_calls_map_mcp_tools_and_wrapped_cli_without_payload_retention(self):
        index = telemetry.command_index(telemetry.TOOLS)
        calls = {
            "mcp__doppelbrain__get_recent_knowledge": "doppelbrain",
            "mcp__cmem__search": "cmem",
            "mcp__headroom__stats": "headroom",
            "mcp__h5i__recall": "h5i",
            "mcp__codex_tui__list_threads": "codex_tui",
        }
        for name, expected in calls.items():
            self.assertEqual(telemetry.function_usage({"type": "tool_use", "name": name, "input": {}}, index), {expected})
        self.assertEqual(telemetry.shell_usage_keys("pnpm --silent exec semgrep --config private", index), {"semgrep"})
        self.assertEqual(telemetry.shell_usage_keys("npx @scope/codeweb | rg secret", index), {"codeweb", "ripgrep"})

    def test_shell_usage_ignores_non_executable_arguments_and_keeps_wrappers(self):
        index = telemetry.command_index(telemetry.TOOLS)
        self.assertEqual(telemetry.shell_usage_keys("echo codeweb", index), set())
        self.assertEqual(telemetry.shell_usage_keys("python script.py semgrep", index), set())
        self.assertEqual(telemetry.shell_usage_keys("h5i capture run -- rg private", index), {"h5i", "ripgrep"})
        self.assertEqual(telemetry.shell_usage_keys("pnpm exec semgrep", index), {"semgrep"})

    def test_shell_and_custom_usage_ignore_heredocs_and_literal_tool_names(self):
        index = telemetry.command_index(telemetry.TOOLS)
        heredoc = "cat <<'PY'\nrg mentioned-only\nh5i mentioned-only\nPY\nsemgrep --version"
        self.assertEqual(telemetry.shell_usage_keys(heredoc, index), {"semgrep"})
        self.assertEqual(telemetry.custom_input_usage({"cmd": heredoc}, index), {"semgrep"})
        self.assertEqual(
            telemetry.custom_input_usage("const example = 'tools.mcp__cmem__search({})';", index),
            set(),
        )
        self.assertEqual(
            telemetry.custom_input_usage("// tools.mcp__cmem__search({})\ntext('not called');", index),
            set(),
        )
        self.assertEqual(
            telemetry.custom_input_usage("await tools.mcp__cmem__search({});", index),
            {"cmem"},
        )

    def test_codex_command_execution_counts_completed_shell_command_once(self):
        index = telemetry.command_index(telemetry.TOOLS)
        event = {
            "type": "event_msg",
            "timestamp": "2026-09-01T00:00:01Z",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "CommandExecution",
                    "command": ["/bin/zsh", "-lc", "h5i capture run -- rg private"],
                    "status": "completed",
                    "exit_code": 0,
                },
            },
        }
        records = telemetry.tool_call_records(event, index)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["keys"], {"h5i", "ripgrep"})
        self.assertEqual(records[0]["completed_error"], False)
        event["payload"]["item"]["command"] = ["echo", "rg"]
        self.assertEqual(telemetry.tool_call_records(event, index), [])

    def test_exec_envelope_plus_command_completion_counts_cli_once(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        session = self.codex / "completed-command.jsonl"
        session.write_text("\n".join((
            json.dumps({"type": "response_item", "payload": {
                "type": "custom_tool_call", "name": "exec", "input": 'await tools.exec_command({cmd:"rg source"});',
            }}),
            json.dumps({"type": "event_msg", "timestamp": "2026-09-01T00:00:01Z", "payload": {
                "type": "item_completed", "item": {
                    "type": "CommandExecution", "command": ["/bin/zsh", "-lc", "rg source"],
                    "status": "completed", "exit_code": 0,
                },
            }}),
        )) + "\n", encoding="utf-8")
        event = telemetry.collect_sample(
            self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools,
        )
        self.assertEqual(event["tools"]["ripgrep"]["user_usage"], {"codex_jsonl": 1})
        self.assertEqual((event["outcomes"]["ripgrep"]["calls"], event["outcomes"]["ripgrep"]["success"]), (1, 1))

    def test_codex_mcp_completion_is_authoritative_over_exec_source(self):
        index = telemetry.command_index(telemetry.TOOLS)
        exec_source = {
            "type": "custom_tool_call",
            "name": "exec",
            "input": "await tools.mcp__cmem__search({});",
        }
        self.assertEqual(telemetry.function_usage(exec_source, index), set())
        completed = {
            "type": "event_msg",
            "timestamp": "2026-09-01T00:00:01Z",
            "payload": {"type": "item_completed", "item": {
                "type": "McpToolCall", "server": "cmem", "tool": "search", "status": "completed",
            }},
        }
        records = telemetry.tool_call_records(completed, index)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["keys"], {"cmem"})
        self.assertEqual(records[0]["completed_error"], False)

    def test_excluded_audit_session_advances_cursor_without_counting_usage(self):
        self.history.write_text("", encoding="utf-8")
        audit_session = self.codex / "audit.jsonl"
        audit_session.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        telemetry.exclude_session(self.state_dir, audit_session)
        audit_session.write_text(json.dumps({
            "type": "response_item",
            "payload": {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "rg audit-only"})},
        }) + "\n", encoding="utf-8")
        event = telemetry.collect_sample(
            self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools,
        )
        self.assertEqual(event["tools"]["ripgrep"]["user_usage"], {})
        self.assertEqual(event["source_activity"]["codex_jsonl"], 0)
        state = telemetry.load_state(self.state_dir)
        self.assertEqual(len(state["excluded_event_fingerprints"]), 1)
        self.assertNotIn(str(audit_session), json.dumps(state))

    def test_jsonl_partial_line_is_retried_after_append(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        event_file = self.codex / "partial.jsonl"
        line = json.dumps({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "rg incomplete"})}})
        event_file.write_text(line[:-4], encoding="utf-8")
        first = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=False)
        self.assertEqual(first["tools"]["ripgrep"]["user_usage"], {})
        fingerprint = telemetry.path_fingerprint(event_file)
        self.assertEqual(telemetry.load_state(self.state_dir)["event_cursors"]["codex_jsonl"][fingerprint]["offset"], 0)
        with event_file.open("a", encoding="utf-8") as handle:
            handle.write(line[-4:] + "\n")
        second = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=False)
        self.assertEqual(second["tools"]["ripgrep"]["user_usage"], {"codex_jsonl": 1})

    def test_audit_probes_use_real_capabilities(self):
        by_key = {tool.key: tool for tool in telemetry.TOOLS}
        self.assertEqual(by_key["segundocerebro"].probe, ("sc", "--help"))
        self.assertEqual(by_key["segundocerebro"].probe_timeout_seconds, 20.0)
        self.assertEqual(by_key["codeweb"].probe, ())
        self.assertEqual(by_key["codeweb"].cli_commands, ())
        self.assertEqual(by_key["semgrep"].probe, ("semgrep", "--version", "--disable-version-check"))
        self.assertEqual(by_key["doppelbrain"].probe, ("dbrain-mcp-proxy", "--help"))

    def test_process_metrics_uses_executable_identity_and_safe_wrappers(self):
        codebase_memory = telemetry.Tool("codebase_memory_mcp", "codebase-memory-mcp", ("codebase-memory-mcp",), ("codebase-memory-mcp",))
        codex = telemetry.Tool("codex_tui", "codex-tui", ("codex",), ("codex",))
        rows = (
            (1.0, 10, 20, "earlyoom --prefer '(codebase-memory-mcp)'"),
            (2.0, 20, 30, "systemd-inhibit --who codex --what=sleep"),
            (3.0, 30, 40, "env TOOL_MODE=stdio /usr/local/bin/codebase-memory-mcp --stdio"),
            (4.0, 40, 50, "systemd-inhibit --what=sleep -- /usr/local/bin/codex --dangerously-bypass-approvals"),
        )
        self.assertEqual(telemetry.process_metrics(codebase_memory, rows), {"count": 1, "cpu_percent": 3.0, "rss_kib": 30, "uptime_seconds": 40})
        self.assertEqual(telemetry.process_metrics(codex, rows), {"count": 1, "cpu_percent": 4.0, "rss_kib": 40, "uptime_seconds": 50})

    def test_process_matcher_recognises_resident_entrypoints_only_under_known_roots(self):
        tools = {tool.key: tool for tool in telemetry.TOOLS}
        resident_snapshot = (
            (1.0, 11, 101, "/usr/bin/python3 /home/freedom/freedomdigitalhub/workspace/freedom-os/memory/segundocerebro/apps/mcp-server/server/mcp_server_v2.py", "/usr/bin/python3"),
            (2.0, 12, 102, "node /home/freedom/.claude/plugins/cache/codeweb/codeweb/0.13.0/scripts/mcp-server.mjs", "/usr/bin/node"),
            (3.0, 13, 103, "/home/freedom/.bun/bin/bun /home/freedom/.claude/plugins/cache/context-mode/context-mode/1.0.169/start.mjs", "/home/freedom/.bun/bin/bun"),
            (4.0, 14, 104, "node /home/freedom/.claude/plugins/cache/thedotmack/claude-mem/13.21.1/scripts/mcp-server.cjs", "/usr/bin/node"),
            (5.0, 15, 105, "/usr/bin/python3.12 /home/freedom/.local/bin/headroom mcp serve", "/usr/bin/python3.12"),
            (6.0, 16, 106, "/usr/bin/python3 /home/freedom/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.22/server.py", "/usr/bin/python3"),
            (7.0, 17, 107, "/usr/bin/python3.12 -m headroom.cli proxy --port 8787", "/usr/bin/python3.12"),
            (8.0, 18, 108, "/home/freedom/.local/share/uv/tools/chroma-mcp/bin/chroma-mcp", "/home/freedom/.local/share/uv/tools/chroma-mcp/bin/chroma-mcp"),
            (9.0, 19, 109, "uv run chroma-mcp", "/home/freedom/.local/bin/uv"),
        )
        expected_counts = {
            "segundocerebro": 1,
            "codeweb": 1,
            "context_mode": 1,
            "claude_mem": 3,
            "headroom": 2,
            "codex_security": 1,
        }
        for key, expected_count in expected_counts.items():
            self.assertEqual(telemetry.process_metrics(tools[key], resident_snapshot)["count"], expected_count)

        outside_roots = (
            (7.0, 17, 107, "node /tmp/mcp-server.mjs", "/usr/bin/node"),
            (8.0, 18, 108, "earlyoom --prefer '(codebase-memory-mcp)'", "/usr/bin/earlyoom"),
            (9.0, 19, 109, "systemd-inhibit --who codex --what=sleep", "/usr/bin/systemd-inhibit"),
            (10.0, 20, 110, "/usr/bin/python3 -m headroom.cli_extra proxy", "/usr/bin/python3"),
            (11.0, 21, 111, "/tmp/chroma-mcp-helper", "/tmp/chroma-mcp-helper"),
        )
        for key in expected_counts:
            self.assertEqual(telemetry.process_metrics(tools[key], outside_roots)["count"], 0)
        self.assertEqual(telemetry.process_metrics(tools["codex_tui"], outside_roots)["count"], 0)

    def test_ast_grep_and_ripgrep_require_their_real_executable_paths(self):
        tools = {tool.key: tool for tool in telemetry.TOOLS}
        paths = {"ast-grep": "/opt/tools/ast-grep", "sg": "/opt/tools/sg", "rg": "/opt/tools/rg", "ripgrep": "/opt/tools/ripgrep"}
        rows = (
            (1.0, 10, 20, "/opt/tools/rg --version", "/opt/tools/rg"),
            (2.0, 20, 30, "/tmp/rg --version", "/tmp/rg"),
            (3.0, 30, 40, "/opt/tools/ast-grep scan", "/opt/tools/ast-grep"),
            (4.0, 40, 50, "/tmp/sg scan", "/tmp/sg"),
        )
        with patch.object(telemetry.shutil, "which", side_effect=lambda command: paths.get(command)):
            self.assertEqual(telemetry.process_metrics(tools["ripgrep"], rows)["count"], 1)
            self.assertEqual(telemetry.process_metrics(tools["ast_grep"], rows)["count"], 1)

    def test_systemd_units_use_private_network_not_unsupported_ip_firewall(self):
        systemd_directory = MODULE_PATH.parent / "systemd"
        for unit_name in ("tool-telemetry-sample.service", "tool-telemetry-finalize.service"):
            contents = (systemd_directory / unit_name).read_text(encoding="utf-8")
            self.assertIn("PrivateNetwork=yes", contents)
            self.assertNotIn("IPAddressDeny=", contents)
            self.assertNotIn("IPAddressAllow=", contents)

    def test_report_excludes_legacy_process_metrics_but_preserves_the_event(self):
        self.history.write_text("", encoding="utf-8")
        state = telemetry.initialise(self.state_dir, self.history, self.event_roots())
        telemetry.append_event(self.state_dir, {
            "at": state["window_start"], "kind": "sample", "run_id": state["run_id"],
            "usage_parser_version": telemetry.USAGE_PARSER_VERSION,
            "process_matcher_version": 1,
            "tools": {"ripgrep": {"cli_present": True, "process": {"cpu_percent": 99.0, "rss_kib": 9999}, "user_usage": {}}},
        })
        telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools, force_deep=False)
        report = telemetry.markdown_report(self.state_dir, self.tools)
        self.assertIn("1 amostras legadas preservadas, porém excluídas", report)
        self.assertNotIn("9999 KiB", report)

    def test_semgrep_probe_uses_private_settings_and_disables_metrics(self):
        semgrep = next(tool for tool in telemetry.TOOLS if tool.key == "semgrep")
        completed = telemetry.subprocess.CompletedProcess(semgrep.probe, 0, stdout=b"1.2.3\n", stderr=b"")
        with patch.object(telemetry.shutil, "which", return_value="/bin/semgrep"), patch.object(
            telemetry.subprocess, "run", return_value=completed
        ) as run:
            result = telemetry.probe(semgrep)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["SEMGREP_SEND_METRICS"], "off")
        self.assertTrue(environment["SEMGREP_SETTINGS_FILE"].endswith("tool-telemetry-semgrep/settings.yml"))
        self.assertTrue(environment["SEMGREP_LOG_FILE"].endswith("tool-telemetry-semgrep/semgrep.log"))
        self.assertEqual(result["exit_code"], 0)

    def test_custom_tool_calls_count_mcp_and_delegated_executables_without_output(self):
        index = telemetry.command_index(telemetry.TOOLS)
        wrapper_call = {
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "input": json.dumps({"cmd": "h5i capture run -- rg confidential-value"})},
        }
        self.assertEqual(telemetry.function_usage(wrapper_call, index), {"h5i", "ripgrep"})
        mcp_call = {
            "type": "custom_tool_call",
            "name": "exec",
            "input": "await tools.mcp__doppelbrain__get_recent_knowledge({}); await tools.mcp__cmem__search({});",
        }
        self.assertEqual(telemetry.function_usage(mcp_call, index), set())
        self.assertEqual(telemetry.function_usage({"type": "custom_tool_call_output", "output": "rg confidential-value"}, index), set())

    def test_jsonl_correlates_codex_and_claude_outputs_without_persisting_call_ids_or_content(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        tracked = (
            telemetry.Tool("doppelbrain", "DoppelBrain", ("doppelbrain",), ("unlikely-process",)),
            telemetry.Tool("cmem", "cmem", ("cmem",), ("unlikely-process",)),
        )
        codex_session = self.codex / "custom.jsonl"
        codex_session.write_text(json.dumps({
            "type": "response_item", "payload": {
                "type": "function_call", "name": "mcp__doppelbrain__get_recent_knowledge", "call_id": "codex-private-call-id",
                "timestamp": "2026-09-01T00:00:00Z", "arguments": "{}",
            },
        }) + "\n", encoding="utf-8")
        first = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=tracked, force_deep=False)
        self.assertEqual(first["outcomes"]["doppelbrain"]["calls"], 1)
        self.assertEqual(first["outcomes"]["doppelbrain"]["attribution"]["direct"], 1)
        self.assertNotIn("codex-private-call-id", json.dumps(telemetry.load_state(self.state_dir)))
        with codex_session.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"type": "response_item", "payload": {
                "type": "function_call_output", "call_id": "codex-private-call-id", "timestamp": "2026-09-01T00:00:01Z",
                "output": json.dumps({"exit_code": 0, "message": "private-output"}),
            }}) + "\n")
        claude_session = self.claude / "tool-result.jsonl"
        claude_session.write_text("\n".join((
            json.dumps({"type": "assistant", "timestamp": "2026-09-01T00:00:02Z", "message": {"content": [{"type": "tool_use", "id": "claude-private-tool-id", "name": "mcp__cmem__search", "input": {}}]}}),
            json.dumps({"type": "user", "timestamp": "2026-09-01T00:00:04Z", "message": {"content": [{"type": "tool_result", "tool_use_id": "claude-private-tool-id", "is_error": True, "content": "private-error-output"}]}}),
        )) + "\n", encoding="utf-8")
        second = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=tracked, force_deep=False)
        doppel = second["outcomes"]["doppelbrain"]
        cmem = second["outcomes"]["cmem"]
        self.assertEqual((doppel["success"], doppel["unknown"], doppel["latency_ms"]["sum"]), (1, 0, 1000))
        self.assertEqual((cmem["calls"], cmem["error"], cmem["attribution"]["direct"]), (1, 1, 1))
        self.assertEqual(cmem["latency_ms"]["sum"], 2000)
        persisted = (self.state_dir / telemetry.EVENTS_FILE).read_text(encoding="utf-8") + json.dumps(telemetry.load_state(self.state_dir))
        self.assertNotIn("private-call-id", persisted)
        self.assertNotIn("private-output", persisted)
        self.assertNotIn("private-error-output", persisted)

    def test_completed_mcp_items_record_individual_outcomes(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        tracked = (
            telemetry.Tool("doppelbrain", "DoppelBrain", ("doppelbrain",), ("unlikely-process",)),
            telemetry.Tool("cmem", "cmem", ("cmem",), ("unlikely-process",)),
        )
        session = self.codex / "array-output.jsonl"
        session.write_text("\n".join((
            json.dumps({"type": "event_msg", "timestamp": "2026-09-01T00:00:01Z", "payload": {"type": "item_completed", "item": {"type": "McpToolCall", "server": "doppelbrain", "tool": "get_recent_knowledge", "status": "completed"}}}),
            json.dumps({"type": "event_msg", "timestamp": "2026-09-01T00:00:02Z", "payload": {"type": "item_completed", "item": {"type": "McpToolCall", "server": "cmem", "tool": "search", "status": "failed"}}}),
        )) + "\n", encoding="utf-8")
        event = telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=tracked, force_deep=False)
        self.assertEqual((event["outcomes"]["doppelbrain"]["calls"], event["outcomes"]["doppelbrain"]["success"]), (1, 1))
        self.assertEqual((event["outcomes"]["cmem"]["calls"], event["outcomes"]["cmem"]["error"]), (1, 1))

    def test_headroom_stats_uses_safe_deltas_only(self):
        payload = json.dumps({"lifetime": {"calls": 12, "cost_usd": 1.25, "tokens_saved": 999}, "path": "/private"}).encode()
        with patch.object(telemetry.shutil, "which", return_value="/bin/headroom"), patch.object(telemetry.subprocess, "run", return_value=telemetry.subprocess.CompletedProcess([], 0, stdout=payload, stderr=b"")):
            observation, snapshot = telemetry.headroom_stats({"calls": 10, "cost_usd": 1.0})
        self.assertEqual(observation, {"status": "available", "calls_delta": 2, "cost_usd_delta": 0.25})
        self.assertEqual(snapshot, {"calls": 12, "cost_usd": 1.25})

    def test_claude_mem_db_counts_only_and_keeps_content_private(self):
        database = self.root / "claude-mem.db"
        connection = sqlite3.connect(database)
        try:
            for table in telemetry.CLAUDE_MEM_TABLES:
                connection.execute(f"CREATE TABLE {table} (created_at_epoch INTEGER, secret TEXT)")
                connection.execute(f"INSERT INTO {table} VALUES (?, ?)", (1, "private-prompt-or-title"))
            connection.commit()
        finally:
            connection.close()
        observation, snapshot = telemetry.claude_mem_db_stats({table: 0 for table in telemetry.CLAUDE_MEM_TABLES}, database)
        self.assertEqual(observation["status"], "available")
        self.assertEqual(observation["deltas"], {table: 1 for table in telemetry.CLAUDE_MEM_TABLES})
        self.assertEqual(snapshot, {table: 1 for table in telemetry.CLAUDE_MEM_TABLES})
        self.assertNotIn("private-prompt-or-title", json.dumps({"observation": observation, "snapshot": snapshot}))

    def test_representative_activity_uses_source_event_days_not_sample_days(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        state = telemetry.load_state(self.state_dir)

        def append_week(activity_days):
            for day in range(8):
                telemetry.append_event(self.state_dir, {
                    "kind": "sample", "run_id": state["run_id"], "at": f"2026-09-{day + 1:02d}T00:00:00+00:00",
                    "usage_parser_version": telemetry.USAGE_PARSER_VERSION,
                    "source_activity": {"codex_jsonl": activity_days.get(day, 0), "claude_jsonl": 0}, "tools": {},
                })

        with patch.object(telemetry, "EXPECTED_SAMPLES", 8):
            append_week({0: 20})
            self.assertIn("Decisão da execução: **INCONCLUSIVA**", telemetry.markdown_report(self.state_dir, self.tools))
            telemetry.initialise(self.state_dir, self.history, self.event_roots(), new_run=True)
            state = telemetry.load_state(self.state_dir)
            append_week({0: 8, 3: 6, 7: 6})
            self.assertIn("Decisão da execução: **EVIDÊNCIA SUFICIENTE PARA REVISÃO CONTROLADA**", telemetry.markdown_report(self.state_dir, self.tools))
            telemetry.initialise(self.state_dir, self.history, self.event_roots(), new_run=True)
            state = telemetry.load_state(self.state_dir)
            append_week({1: 7, 7: 7})
            telemetry.append_event(self.state_dir, {
                "kind": "sample", "run_id": state["run_id"], "at": "2026-08-31T00:00:00+00:00",
                "source_activity": {"codex_jsonl": 6, "claude_jsonl": 0}, "tools": {},
            })
            self.assertIn("Decisão da execução: **INCONCLUSIVA**", telemetry.markdown_report(self.state_dir, self.tools))

    def test_report_excludes_usage_from_legacy_parser_samples(self):
        self.history.write_text("", encoding="utf-8")
        state = telemetry.initialise(self.state_dir, self.history, self.event_roots())
        common = {"kind": "sample", "run_id": state["run_id"], "deep": False, "source_activity": {}}
        telemetry.append_event(self.state_dir, {
            **common,
            "at": "2026-09-01T00:00:00+00:00",
            "tools": {"ripgrep": {"user_usage": {"codex_jsonl": 999}}},
            "outcomes": {"ripgrep": {"calls": 999}},
        })
        telemetry.append_event(self.state_dir, {
            **common,
            "at": "2026-09-01T00:05:00+00:00",
            "usage_parser_version": telemetry.USAGE_PARSER_VERSION,
            "tools": {"ripgrep": {"user_usage": {"codex_jsonl": 1}}},
            "outcomes": {"ripgrep": {"calls": 1}},
        })
        report = telemetry.markdown_report(self.state_dir, self.tools)
        ripgrep_row = next(line for line in report.splitlines() if line.startswith("| ripgrep |"))
        self.assertEqual([cell.strip() for cell in ripgrep_row.split("|")][3], "1")
        self.assertIn(f"Métricas de invocação válidas (parser v{telemetry.USAGE_PARSER_VERSION}): 1/2016", report)
        self.assertIn("1 amostras de bootstrap excluídas", report)

    def test_init_creates_new_168_hour_run_and_report_excludes_old_run(self):
        self.history.write_text("", encoding="utf-8")
        first = telemetry.initialise(self.state_dir, self.history, self.event_roots())
        old_run = first["run_id"]
        second = telemetry.initialise(self.state_dir, self.history, self.event_roots(), new_run=True)
        self.assertNotEqual(old_run, second["run_id"])
        start = telemetry.dt.datetime.fromisoformat(second["window_start"])
        end = telemetry.dt.datetime.fromisoformat(second["window_end"])
        self.assertEqual(end - start, telemetry.dt.timedelta(hours=168))
        telemetry.append_event(self.state_dir, {"kind": "sample", "run_id": old_run, "tools": {"ripgrep": {"user_usage": {"zsh_history": 999}}}})
        report = telemetry.markdown_report(self.state_dir, self.tools)
        self.assertNotIn("999", report)

    def test_expired_window_does_not_append_sample_and_finalize_is_idempotent(self):
        self.history.write_text("", encoding="utf-8")
        telemetry.initialise(self.state_dir, self.history, self.event_roots())
        state = telemetry.load_state(self.state_dir)
        state["window_end"] = "2000-01-01T00:00:00+00:00"
        telemetry.write_json_atomic(self.state_dir / telemetry.STATE_FILE, state)
        with self.assertRaises(telemetry.WindowExpired):
            telemetry.collect_sample(self.state_dir, history_path=self.history, event_roots=self.event_roots(), tools=self.tools)
        self.assertEqual(sum(event.get("kind") == "sample" for event in telemetry.read_events(self.state_dir)), 0)
        output = self.root / "final.md"
        self.assertEqual(telemetry.main(["finalize", "--state-dir", str(self.state_dir), "--output", str(output)]), 0)
        self.assertEqual(telemetry.main(["finalize", "--state-dir", str(self.state_dir), "--output", str(output)]), 0)
        self.assertEqual(sum(event.get("kind") == "finalised" for event in telemetry.read_events(self.state_dir)), 1)


if __name__ == "__main__":
    unittest.main()
