#!/usr/bin/env python3
"""Check preparation without installing packages or changing the host."""
from pathlib import Path
import re
import os
import tempfile
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrepareTests(unittest.TestCase):
    def prepare(self, distro, go_installed=True, fail_update=False):
        script = (ROOT / 'deploy/provision.sh').read_text()
        function = re.search(r'^function prepare_system\(\) \{\n.*?^\}', script,
                             re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(function, 'prepare_system function is missing')
        harness = '''set -e
log() { :; }
_log() { echo "$*" >&2; }
package_repo_update() { echo update; return "$FAIL_UPDATE"; }
sudo() { printf 'package %s\\n' "$@"; }
install_go_27() { echo install-go; }
install_nvm() { echo install-node; }
command() { if [[ "$*" == '-v go' ]]; then return "$GO_MISSING"; else builtin command "$@"; fi; }
'''
        return subprocess.run(['bash', '-c', harness + function.group() + '\nprepare_system "$DISTRO"'],
                              env={'DISTRO': distro, 'FAIL_UPDATE': str(int(fail_update)),
                                   'GO_MISSING': str(int(not go_installed))},
                              capture_output=True, text=True)

    def test_build_dependencies_exclude_services(self):
        for distro, compiler in [('ubuntu', 'build-essential'), ('debian', 'build-essential'),
                                 ('centos', 'gcc')]:
            with self.subTest(distro=distro):
                result = self.prepare(distro, go_installed=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('package ' + compiler, result.stdout)
                self.assertIn('install-go', result.stdout)
                self.assertIn('install-node', result.stdout)
                for service in ('nginx', 'postgres', 'redis', 'systemctl', 'osquery'):
                    self.assertNotIn(service, result.stdout)

    def test_prepare_exits_before_service_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'deploy').mkdir()
            (root / 'deploy/lib.sh').write_text('log() { :; }\n_log() { echo "$*" >&2; }\npackage_repo_update() { :; }\nsudo() { :; }\ninstall_go_27() { :; }\ninstall_nvm() { :; }\nprepare_deployment() { echo \'unexpected deployment\' >&2; return 73; }\n')
            startup = root / 'startup.sh'
            # Isolate GNU getopt, which is not provided by macOS.
            startup.write_text('getopt() { printf "%s\\n" "--prepare -s $TEST_SOURCE --nginx --postgres --redis --upgrade --"; }\n')
            result = subprocess.run(['bash', str(ROOT / 'deploy/provision.sh'), '--prepare'],
                                    env=os.environ | {'BASH_ENV': str(startup),
                                                      'TEST_SOURCE': directory, 'DISTRO': 'ubuntu'},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('unexpected deployment', result.stderr)

    def test_existing_go_is_preserved(self):
        result = self.prepare('debian')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('install-go', result.stdout)

    def test_unsupported_distro_and_update_failure_stop_preparation(self):
        for distro, fail_update in [('unsupported', False), ('ubuntu', True)]:
            with self.subTest(distro=distro):
                result = self.prepare(distro, fail_update=fail_update)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('install-node', result.stdout)
                self.assertNotIn('package ', result.stdout)


if __name__ == '__main__':
    unittest.main()
