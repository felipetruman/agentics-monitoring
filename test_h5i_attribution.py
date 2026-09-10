"""Regression coverage for capture outcomes, pending calls and legacy reports."""
import json
import tempfile
import unittest
from pathlib import Path

import tool_telemetry as telemetry


class H5iAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = telemetry.command_index(telemetry.TOOLS)

    def read_events(self, events, cursors=None, pending=None):
        with (self.root / 'session.jsonl').open('a') as handle:
            for event in events:
                handle.write(json.dumps(event) + '\n')
        return telemetry.count_jsonl_usage(self.root, cursors or {}, self.index, pending or {})

    def completed(self, command, code):
        return {'type': 'event_msg', 'payload': {'type': 'item_completed', 'item': {
            'type': 'CommandExecution', 'command': command,
            'status': 'failed' if code else 'completed', 'exit_code': code,
        }}}

    def test_capture_failures_and_successes_do_not_become_h5i_outcomes(self):
        for command in ('h5i capture run -- rg private-value',
                        ['/bin/zsh', '-lc', 'h5i capture run -- bash -c "exit 1"'],
                        ['/usr/bin/h5i', 'capture', 'run', '--file', 'private-path', '--', 'false']):
            with self.subTest(command=command):
                for code in (0, 1, 2, 3):
                    record = telemetry.tool_call_records(self.completed(command, code), self.index)[0]
                    self.assertTrue(record['h5i_capture'])
        counts, cursors, outcomes, pending, _ = self.read_events([
            self.completed('h5i capture run -- rg private-value', 1),
            self.completed(['h5i', 'capture', 'run', '--', 'true'], 0),
            self.completed('h5i recall invalid-command', 2),
        ])
        h5i = outcomes['h5i']
        self.assertEqual((h5i['calls'], h5i['success'], h5i['error'], h5i['unknown']), (3, 0, 1, 2))
        self.assertEqual((h5i['capture_exit_zero'], h5i['capture_exit_nonzero']), (1, 1))
        self.assertEqual(outcomes['ripgrep']['error'], 1)
        self.assertNotIn('private-value', json.dumps([counts, cursors, outcomes, pending]))

    def test_non_capture_commands_and_literals_do_not_match(self):
        for command in ('h5i recall search capture', 'echo "h5i capture run -- false"',
                        'h5i capture run --help', 'h5i capture run --',
                        "cat <<'EOF'\nh5i capture run -- false\nEOF", "'broken"):
            with self.subTest(command=command):
                self.assertFalse(telemetry.is_h5i_capture(command))
        self.assertTrue(telemetry.is_h5i_capture('H5I_AGENT=codex h5i capture run -- false'))

    def test_claude_pending_capture_is_preserved_across_samples(self):
        call = {'type': 'assistant', 'timestamp': '2026-09-10T00:00:00Z', 'message': {'content': [{
            'type': 'tool_use', 'id': 'private-call-id', 'name': 'Bash',
            'input': {'command': 'h5i capture run -- false private-content'},
        }]}}
        counts, cursors, outcomes, pending, _ = self.read_events([call])
        self.assertEqual(counts['h5i'], 1)
        self.assertNotIn('private', json.dumps(pending))
        result = {'type': 'user', 'timestamp': '2026-09-10T00:00:01Z', 'message': {'content': [{
            'type': 'tool_result', 'tool_use_id': 'private-call-id', 'is_error': True, 'content': 'private-output',
        }]}}
        _, _, outcomes, pending, _ = self.read_events([result], cursors, pending)
        self.assertEqual(outcomes['h5i']['error'], 0)
        self.assertEqual(outcomes['h5i']['capture_exit_nonzero'], 1)
        self.assertEqual(outcomes['h5i']['unknown'], 1)
        self.assertEqual(outcomes['h5i']['latency_ms']['count'], 0)
        self.assertEqual(pending, {})

    def test_old_pending_is_unknown_and_direct_call_still_records_error(self):
        for entry, expected in (({'keys': ['h5i']}, 'unknown'),
                                ({'keys': ['h5i'], 'h5i_capture': False}, 'error')):
            outcomes = {}
            telemetry.add_outcome_result(outcomes, entry, True, None, False)
            self.assertEqual(outcomes['h5i'][expected], 1)

    def test_report_preserves_legacy_events_and_separates_capture_counts(self):
        state_dir = self.root / 'state'
        state_dir.mkdir()
        telemetry.write_json_atomic(state_dir / telemetry.STATE_FILE, {'run_id': 'test'})
        common = {'kind': 'sample', 'run_id': 'test', 'usage_parser_version': telemetry.USAGE_PARSER_VERSION}
        telemetry.append_event(state_dir, {**common, 'outcomes': {'h5i': {
            'calls': 10, 'success': 7, 'error': 3, 'unknown': 0,
        }}})
        telemetry.append_event(state_dir, {**common,
            'outcome_attribution_version': telemetry.OUTCOME_ATTRIBUTION_VERSION,
            'outcomes': {'h5i': {'calls': 3, 'success': 0, 'error': 1, 'unknown': 2,
                                 'capture_exit_zero': 1, 'capture_exit_nonzero': 1}},
        })
        before = (state_dir / telemetry.EVENTS_FILE).read_bytes()
        report = telemetry.markdown_report(state_dir, (next(t for t in telemetry.TOOLS if t.key == 'h5i'),))
        self.assertIn('chamadas/sucesso/erro/desconhecido 13/0/1/12', report)
        self.assertIn('captura saída zero/não zero 1/1', report)
        self.assertIn('erros legados sem atribuição 3', report)
        self.assertEqual(before, (state_dir / telemetry.EVENTS_FILE).read_bytes())


if __name__ == '__main__':
    unittest.main()
