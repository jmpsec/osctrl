#!/usr/bin/env python3

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import debug_tls_endpoints


class ParseFlagsTest(unittest.TestCase):
    def test_parse_flags_supports_equals_and_split_forms(self):
        parsed = debug_tls_endpoints.parse_flags_text(
            "\n".join(
                [
                    "--tls_hostname=osctrl.example.com",
                    "--config_tls_endpoint /env/config",
                    "--logger_tls_endpoint=/env/log",
                    "--distributed_tls_read_endpoint /env/read",
                    "--distributed_tls_write_endpoint=/env/write",
                    "--enroll_secret_path /tmp/osquery.secret",
                    "--tls_server_certs=/tmp/osctrl.crt",
                ]
            )
        )

        self.assertEqual(parsed["tls_hostname"], "osctrl.example.com")
        self.assertEqual(parsed["config_tls_endpoint"], "/env/config")
        self.assertEqual(parsed["logger_tls_endpoint"], "/env/log")
        self.assertEqual(parsed["distributed_tls_read_endpoint"], "/env/read")
        self.assertEqual(parsed["distributed_tls_write_endpoint"], "/env/write")
        self.assertEqual(parsed["enroll_secret_path"], "/tmp/osquery.secret")
        self.assertEqual(parsed["tls_server_certs"], "/tmp/osctrl.crt")

    def test_normalize_host_defaults_to_https(self):
        self.assertEqual(
            debug_tls_endpoints.normalize_host("osctrl.example.com"),
            "https://osctrl.example.com",
        )


if __name__ == "__main__":
    unittest.main()
