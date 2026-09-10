import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import tool_telemetry as telemetry


class ReviewRegressionTests(unittest.TestCase):
    def test_shell_literals_are_not_invocations(self):
        index = telemetry.command_index(telemetry.TOOLS)
        for command in (
            'echo "example; rg secret"', 'printf "%s" -- semgrep',
            'echo ";" rg secret', r'echo example\; rg secret',
            'echo "example|semgrep"', 'command -v semgrep', 'env --help rg', "printf '%s' 'rg\nsemgrep'",
            "echo ignored # ; rg secret", "cat <<'EOF'\nrg secret\nEOF\n",
        ):
            with self.subTest(command=command):
                self.assertEqual(telemetry.shell_usage_keys(command, index), set())
                event = {'type': 'event_msg', 'payload': {'type': 'item_completed', 'item': {
                    'type': 'CommandExecution', 'command': ['/bin/bash', '-lc', command],
                    'status': 'completed', 'exit_code': 0,
                }}}
                self.assertEqual(telemetry.function_usage(event, index), set())

    def test_real_boundaries_and_known_wrappers_keep_usage(self):
        index = telemetry.command_index(telemetry.TOOLS)
        cases = {
            'echo "example; rg secret"; semgrep --version': {'semgrep'},
            'rg pattern | semgrep --version': {'ripgrep', 'semgrep'},
            'rg pattern\nsc --help': {'ripgrep', 'segundocerebro'},
            'h5i capture run -- rg private': {'h5i', 'ripgrep'},
            'h5i capture run -- bash -c "rg private; sc --help"': {'h5i', 'ripgrep', 'segundocerebro'},
            'pnpm --silent exec semgrep': {'semgrep'},
            'env MODE=test command rg pattern': {'ripgrep'},
            'rg pattern > semgrep': {'ripgrep'},
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(telemetry.shell_usage_keys(command, index), expected)
                self.assertEqual(telemetry.argv_usage_keys(['/bin/zsh', '-lc', command], index), expected)
        self.assertEqual(telemetry.argv_usage_keys(['printf', '%s', '--', 'semgrep'], index), set())
        self.assertEqual(telemetry.argv_usage_keys(['rg', '--', 'semgrep'], index), {'ripgrep'})
        self.assertEqual(telemetry.argv_usage_keys(['h5i', 'capture', 'run', '--', 'rg', 'private'], index), {'h5i', 'ripgrep'})

    def test_production_codebase_memory_process_identity(self):
        tool = next(tool for tool in telemetry.TOOLS if tool.key == 'codebase_memory_mcp')
        rows = [(1.5, 128, 30, '/usr/local/bin/codebase-memory-mcp --stdio'),
                (5.0, 512, 50, '/usr/local/bin/codebase-memory --stdio')]
        self.assertEqual(telemetry.process_metrics(tool, rows),
                         {'count': 1, 'cpu_percent': 1.5, 'rss_kib': 128, 'uptime_seconds': 30})

    def installer_environment(self, root):
        workspace = root / 'workspace'
        workspace.mkdir()
        home = root / 'home'
        home.mkdir()
        binary = root / 'bin'
        binary.mkdir()
        systemctl = binary / 'systemctl'
        systemctl.write_text('''#!/bin/sh
case "$*" in
  *daemon-reload*|*"enable --now"*) test -d "$REPORT_TEST_ROOT/docs" || exit 42 ;;
esac
printf '%s\\n' "$*" >> "$REPORT_TEST_LOG"
''')
        systemctl.chmod(0o700)
        env = {**os.environ, 'HOME': str(home), 'PATH': f'{binary}:/usr/bin:/bin',
               'REPORT_TEST_ROOT': str(workspace), 'REPORT_TEST_LOG': str(root / 'calls.log')}
        args = ['bash', str(Path(__file__).with_name('install.sh')), '--workspace', str(workspace),
                '--state-dir', str(root / 'state'), '--unit-dir', str(root / 'units'),
                '--runtime-dir', str(root / 'runtime')]
        return workspace, env, args

    def test_install_and_start_create_docs_before_unit_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace, env, args = self.installer_environment(root)
            for action in ('install', 'start'):
                if (workspace / 'docs').exists():
                    (workspace / 'docs').rmdir()
                result = subprocess.run([*args, action], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((workspace / 'docs').is_dir())
            sample = (root / 'units/tool-telemetry-sample.service').read_text()
            final = (root / 'units/tool-telemetry-finalize.service').read_text()
            self.assertNotIn(f'ReadWritePaths={root / "state"} {workspace}/docs', sample)
            self.assertIn(f'ReadWritePaths={root / "state"} {workspace}/docs', final)

    def test_dry_run_does_not_create_report_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, env, args = self.installer_environment(Path(directory))
            result = subprocess.run([*args, 'install', '--dry-run'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((workspace / 'docs').exists())


if __name__ == '__main__':
    unittest.main()
