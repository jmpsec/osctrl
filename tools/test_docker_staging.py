#!/usr/bin/env python3
"""Deployment contract tests; requires Docker Compose, but no running daemon."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('OSCTRL_', 'STAGING_', 'POSTGRES_', 'JWT_SECRET'))}
        self.settings = self.directory / 'staging.env'
        self.settings.write_text('OSCTRL_VERSION=1.2.3-test\nJWT_SECRET=' + 'a' * 64 +
                                 '\nPOSTGRES_DB_PASSWORD=db-test\nOSCTRL_PASS=admin-test\n')

    def compose(self, **settings):
        return subprocess.run(['docker', 'compose', '--env-file', str(self.settings),
                               '-f', str(ROOT / 'docker-compose-staging.yml'),
                               'config', '--format', 'json'],
                              env=self.env | settings, capture_output=True, text=True)

    def test_selected_release_is_isolated_and_uses_no_source(self):
        result = self.compose()
        self.assertEqual(result.returncode, 0, result.stderr)
        stack = json.loads(result.stdout)
        self.assertEqual(stack['name'], 'osctrl-staging')
        for component in ('api', 'tls', 'cli', 'frontend'):
            service = stack['services']['osctrl-' + component]
            self.assertEqual(service['image'], f'docker.io/jmpsec/osctrl-{component}:1.2.3-test')
        for service in stack['services'].values():
            self.assertNotIn('build', service)
            self.assertNotIn('develop', service)
            self.assertNotIn('container_name', service)
            for volume in service.get('volumes', []):
                self.assertNotEqual(volume['target'], '/usr/src/app')
        for component in ('api', 'tls', 'frontend'):
            self.assertFalse(stack['services']['osctrl-' + component].get('ports'))
        self.assertEqual({p['published'] for p in stack['services']['osctrl-nginx']['ports']},
                         {'9443', '9444'})
        self.assertTrue(all(p['host_ip'] == '127.0.0.1'
                            for p in stack['services']['osctrl-nginx']['ports']))
        self.assertTrue(all(v['name'].startswith('osctrl-staging_')
                            for v in stack['volumes'].values()))
        for component in ('api', 'tls'):
            self.assertEqual(stack['services']['osctrl-' + component]['depends_on']
                             ['osctrl-cli']['condition'], 'service_completed_successfully')

    def test_database_ports_are_separate_from_development_and_local_only(self):
        for overrides, expected in [({}, ('15432', '16379')),
                                    ({'STAGING_POSTGRES_PORT': '25432',
                                      'STAGING_REDIS_PORT': '26379',
                                      'STAGING_BIND_ADDRESS': '0.0.0.0'}, ('25432', '26379'))]:
            with self.subTest(overrides=overrides):
                result = self.compose(**overrides)
                self.assertEqual(result.returncode, 0, result.stderr)
                services = json.loads(result.stdout)['services']
                for component, target, port in zip(('postgres', 'redis'), (5432, 6379), expected):
                    ports = services['osctrl-' + component]['ports']
                    self.assertEqual(len(ports), 1)
                    self.assertEqual(ports[0]['host_ip'], '127.0.0.1')
                    self.assertEqual(ports[0]['published'], port)
                    self.assertEqual(ports[0]['target'], target)

    def test_release_update_recreates_proxy_with_its_upstreams(self):
        result = subprocess.run(['make', '-n', 'docker_staging_up'], cwd=ROOT,
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--force-recreate', result.stdout)
        self.assertIn('--no-build', result.stdout)
        self.assertIn('--pull always', result.stdout)

    def test_missing_release_and_credentials_fail(self):
        for name in ('OSCTRL_VERSION', 'JWT_SECRET', 'POSTGRES_DB_PASSWORD', 'OSCTRL_PASS'):
            with self.subTest(name=name):
                result = self.compose(**{name: ''})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)

    def bootstrap(self, existing=False, fail=False, environment_only=False):
        cli = self.directory / 'osctrl-cli'
        cli.write_text('''#!/bin/bash
printf '%s\\n' "$*" >> "$TRACE"
case "$*" in
  *"env show"*) [ "$EXISTING" = 1 ] || [ "$ENVIRONMENT_ONLY" = 1 ] ;;
  *show*) [ "$EXISTING" = 1 ] ;;
  *add*) [ "$FAIL_ADD" != 1 ] ;;
esac
''')
        cli.chmod(0o755)
        trace = self.directory / 'trace'
        result = subprocess.run(['bash', str(ROOT / 'deploy/docker/conf/staging/bootstrap.sh')],
                                env=self.env | {'PATH': str(self.directory) + ':' + self.env['PATH'],
                                                'TRACE': str(trace), 'EXISTING': str(int(existing)),
                                                'FAIL_ADD': str(int(fail)),
                                                'ENVIRONMENT_ONLY': str(int(environment_only)),
                                                'OSCTRL_USER': 'admin',
                                                'OSCTRL_PASS': 'password with spaces',
                                                'STAGING_TLS_HOST': 'localhost:9443'},
                                capture_output=True, text=True)
        return result, trace.read_text() if trace.exists() else ''

    def test_bootstrap_creates_environment_and_admin(self):
        result, trace = self.bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('env add --name staging --hostname localhost:9443', trace)
        self.assertIn('user add --admin --username admin', trace)

    def test_bootstrap_user_creation_failure_is_reported(self):
        result, trace = self.bootstrap(fail=True, environment_only=True)
        self.assertIn('user add', trace)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('are ready', result.stdout)

    def test_bootstrap_preserves_existing_environment_and_admin(self):
        result, trace = self.bootstrap(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('add', trace)

    def test_bootstrap_creation_failure_stops_before_user_creation(self):
        result, trace = self.bootstrap(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('user add', trace)


if __name__ == '__main__':
    unittest.main()
