#!/usr/bin/env python3
"""
Comprehensive API tester for osctrl-api service.

Usage:
    python3 api_tester.py <base_url> [options]

Options:
    --username USERNAME    Username for authentication (default: admin)
    --password PASSWORD    Password for authentication
    --env ENV_UUID        Environment UUID to use for testing (required for most tests)
    --token TOKEN         Use existing API token instead of logging in
    --skip-auth           Skip authentication tests
    --verbose             Show detailed request/response information
    --insecure            Disable SSL certificate verification

Examples:
    python3 api_tester.py http://localhost:9002 --env <env-uuid> --username admin --password admin
    python3 api_tester.py https://api.example.com --token <existing-token> --env <env-uuid>
"""

import sys
import json
import argparse
import requests
from typing import Optional, Dict, Any, Tuple, Union, List
from urllib.parse import urljoin

# Disable SSL warnings if insecure flag is used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_PREFIX = "/api/v1"


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class APITester:
    """Comprehensive API tester for osctrl-api"""

    def __init__(self, base_url: str, token: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None,
                 env_uuid: Optional[str] = None, verbose: bool = False,
                 insecure: bool = False):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.username = username
        self.password = password
        self.env_uuid = env_uuid
        self.verbose = verbose
        self.verify_ssl = not insecure
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.test_results = []

    def log(self, message: str, color: str = Colors.RESET):
        """Print colored log message"""
        print(f"{color}{message}{Colors.RESET}")

    def log_verbose(self, message: str):
        """Print verbose log message"""
        if self.verbose:
            self.log(f"  [VERBOSE] {message}", Colors.BLUE)

    def make_request(self, method: str, endpoint: str,
                    headers: Optional[Dict] = None,
                    data: Optional[Dict] = None,
                    expected_status: Optional[Union[int, List[int]]] = None) -> Tuple[bool, Optional[requests.Response], str]:
        """
        Make HTTP request and return (success, response, message)

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            headers: Optional HTTP headers
            data: Optional request data (for POST requests)
            expected_status: Expected HTTP status code(s). Can be a single int or list of ints.
                           If None, any status code is considered valid.

        Returns:
            Tuple of (success, response, message)
        """
        url = urljoin(self.base_url, endpoint)
        if headers is None:
            headers = {}

        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        headers.setdefault('Content-Type', 'application/json')
        headers.setdefault('X-Real-IP', '127.0.0.1')

        try:
            self.log_verbose(f"{method} {url}")
            if data:
                self.log_verbose(f"  Data: {json.dumps(data, indent=2)}")

            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=headers, json=data, timeout=10)
            else:
                return False, None, f"Unsupported method: {method}"

            success = True
            message = f"HTTP {response.status_code}"

            # Normalize expected_status to a list for easier handling
            if expected_status is not None:
                if isinstance(expected_status, int):
                    expected_statuses = [expected_status]
                else:
                    expected_statuses = expected_status

                if response.status_code not in expected_statuses:
                    success = False
                    if len(expected_statuses) == 1:
                        message = f"Expected {expected_statuses[0]}, got {response.status_code}"
                    else:
                        message = f"Expected one of {expected_statuses}, got {response.status_code}"

            if self.verbose:
                try:
                    response_json = response.json()
                    self.log_verbose(f"  Response: {json.dumps(response_json, indent=2)}")
                except:
                    self.log_verbose(f"  Response: {response.text[:200]}")

            return success, response, message

        except requests.exceptions.RequestException as e:
            return False, None, f"Request failed: {str(e)}"

    def test(self, name: str, method: str, endpoint: str,
             headers: Optional[Dict] = None, data: Optional[Dict] = None,
             expected_status: Union[int, List[int]] = 200, skip_if_no_token: bool = False) -> bool:
        """
        Run a single test and record results

        Args:
            name: Test name/description
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            headers: Optional HTTP headers
            data: Optional request data (for POST requests)
            expected_status: Expected HTTP status code(s). Can be a single int or list of ints.
                           Defaults to 200. Test passes if response status matches any of the expected statuses.
            skip_if_no_token: If True, skip test when no token is available

        Returns:
            True if test passed, False otherwise
        """
        # Print request type and URI
        full_url = urljoin(self.base_url, endpoint)
        self.log(f"{method.upper()} {full_url}")

        if skip_if_no_token and not self.token:
            self.log(f"⏭  SKIP: {name} (no token)", Colors.YELLOW)
            self.skipped += 1
            self.test_results.append({
                'name': name,
                'status': 'skipped',
                'reason': 'no token'
            })
            return True

        success, response, message = self.make_request(method, endpoint, headers, data, expected_status)

        if success:
            self.log(f"✓ PASS: {name} - {message}", Colors.GREEN)
            self.passed += 1
            self.test_results.append({
                'name': name,
                'status': 'passed',
                'message': message
            })
            return True
        else:
            self.log(f"✗ FAIL: {name} - {message}", Colors.RED)
            if response:
                try:
                    error_data = response.json()
                    self.log(f"    Error: {error_data.get('error', 'Unknown error')}", Colors.RED)
                except:
                    self.log(f"    Response: {response.text[:200]}", Colors.RED)
            self.failed += 1
            self.test_results.append({
                'name': name,
                'status': 'failed',
                'message': message
            })
            return False

    def login(self, exp_hours: int = 24) -> bool:
        """
        Login and get API token from the response.

        Args:
            exp_hours: Token expiration time in hours (default: 24)

        Returns:
            True if login successful and token obtained, False otherwise
        """
        if not self.username or not self.password or not self.env_uuid:
            self.log("⏭  SKIP: Login (missing username, password, or env_uuid)", Colors.YELLOW)
            if not self.username:
                self.log("    Missing: username", Colors.YELLOW)
            if not self.password:
                self.log("    Missing: password", Colors.YELLOW)
            if not self.env_uuid:
                self.log("    Missing: env_uuid", Colors.YELLOW)
            return False

        endpoint = f"{API_PREFIX}/login/{self.env_uuid}"
        data = {
            "username": self.username,
            "password": self.password,
            "exp_hours": exp_hours
        }

        self.log(f"Attempting login for user '{self.username}' in environment '{self.env_uuid}'...")

        # Make login request without token (since we don't have one yet)
        url = urljoin(self.base_url, endpoint)
        headers = {
            'Content-Type': 'application/json',
            'X-Real-IP': '127.0.0.1'
        }

        try:
            self.log_verbose(f"POST {url}")
            self.log_verbose(f"  Data: {json.dumps({**data, 'password': '***'}, indent=2)}")

            response = self.session.post(url, headers=headers, json=data, timeout=10)

            self.log_verbose(f"  Response status: {response.status_code}")

            if response.status_code == 200:
                try:
                    login_data = response.json()
                    self.log_verbose(f"  Response: {json.dumps(login_data, indent=2)}")

                    # Extract token from response
                    token = login_data.get('token')
                    if token:
                        self.token = token
                        self.log(f"✓ Login successful! Token obtained (length: {len(token)})", Colors.GREEN)
                        return True
                    else:
                        self.log("✗ Login failed: no 'token' field in response", Colors.RED)
                        self.log(f"    Response keys: {list(login_data.keys())}", Colors.RED)
                        return False
                except json.JSONDecodeError as e:
                    self.log(f"✗ Login failed: invalid JSON response", Colors.RED)
                    self.log(f"    Response text: {response.text[:200]}", Colors.RED)
                    return False
            elif response.status_code == 403:
                # Forbidden - invalid credentials or no access
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', 'Unknown error')
                    self.log(f"✗ Login failed: {error_msg}", Colors.RED)
                except:
                    self.log(f"✗ Login failed: Forbidden (HTTP 403)", Colors.RED)
                    self.log(f"    Response: {response.text[:200]}", Colors.RED)
                return False
            elif response.status_code == 400:
                # Bad request - missing or invalid parameters
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', 'Bad request')
                    self.log(f"✗ Login failed: {error_msg}", Colors.RED)
                except:
                    self.log(f"✗ Login failed: Bad request (HTTP 400)", Colors.RED)
                    self.log(f"    Response: {response.text[:200]}", Colors.RED)
                return False
            else:
                # Other error
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', f'HTTP {response.status_code}')
                    self.log(f"✗ Login failed: {error_msg}", Colors.RED)
                except:
                    self.log(f"✗ Login failed: HTTP {response.status_code}", Colors.RED)
                    self.log(f"    Response: {response.text[:200]}", Colors.RED)
                return False

        except requests.exceptions.RequestException as e:
            self.log(f"✗ Login failed: Request exception - {str(e)}", Colors.RED)
            return False

    def run_all_tests(self, skip_auth: bool = False):
        """Run all API tests"""
        self.log(f"\n{Colors.BOLD}=== osctrl API Tester ==={Colors.RESET}\n")
        self.log(f"Base URL: {self.base_url}")
        self.log(f"Environment UUID: {self.env_uuid or 'Not set'}")
        self.log(f"Token: {'Set' if self.token else 'Not set'}\n")

        # Login if needed
        if not self.token and not skip_auth:
            self.log(f"{Colors.BOLD}--- Authentication ---{Colors.RESET}")
            login_success = self.login()
            if login_success:
                self.log(f"Token is now set and will be used for authenticated requests", Colors.GREEN)
            else:
                self.log(f"Warning: Login failed. Some tests will be skipped.", Colors.YELLOW)
            print()

        # Health and status endpoints
        self.log(f"{Colors.BOLD}--- Health & Status ---{Colors.RESET}")
        self.test("Root endpoint", "GET", "/")
        self.test("Health check", "GET", "/health")
        self.test("Check (no auth)", "GET", f"{API_PREFIX}/checks-no-auth")
        self.test("Check (auth)", "GET", f"{API_PREFIX}/checks-auth", skip_if_no_token=True)
        print()

        # Environments
        self.log(f"{Colors.BOLD}--- Environments ---{Colors.RESET}")
        self.test("List all environments", "GET", f"{API_PREFIX}/environments",
                 skip_if_no_token=True)
        if self.env_uuid:
            self.test("Get environment by UUID", "GET",
                     f"{API_PREFIX}/environments/{self.env_uuid}",
                     skip_if_no_token=True)
            self.test("Get environment map (uuid)", "GET",
                     f"{API_PREFIX}/environments/map/uuid",
                     skip_if_no_token=True)
            self.test("Get environment map (name)", "GET",
                     f"{API_PREFIX}/environments/map/name",
                     skip_if_no_token=True)
        print()

        # Platforms
        self.log(f"{Colors.BOLD}--- Platforms ---{Colors.RESET}")
        if self.env_uuid:
            self.test("Get platforms by environment", "GET",
                     f"{API_PREFIX}/platforms/{self.env_uuid}",
                     skip_if_no_token=True)
        print()

        # Nodes
        self.log(f"{Colors.BOLD}--- Nodes ---{Colors.RESET}")
        if self.env_uuid:
            self.test("Get all nodes", "GET",
                     f"{API_PREFIX}/nodes/{self.env_uuid}/all",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
            self.test("Get active nodes", "GET",
                     f"{API_PREFIX}/nodes/{self.env_uuid}/active",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
            self.test("Get inactive nodes", "GET",
                     f"{API_PREFIX}/nodes/{self.env_uuid}/inactive",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
            # Note: These require actual node identifiers, so they may fail
            self.test("Lookup node (test)", "POST",
                     f"{API_PREFIX}/nodes/lookup",
                     data={"identifier": "test-node-identifier"},
                     expected_status=[200, 404],
                     skip_if_no_token=True)
        print()

        # Tags
        self.log(f"{Colors.BOLD}--- Tags ---{Colors.RESET}")
        self.test("List all tags", "GET", f"{API_PREFIX}/tags",
                 skip_if_no_token=True)
        if self.env_uuid:
            self.test("Get tags by environment", "GET",
                     f"{API_PREFIX}/tags/{self.env_uuid}",
                     skip_if_no_token=True)
        print()

        # Settings
        self.log(f"{Colors.BOLD}--- Settings ---{Colors.RESET}")
        self.test("Get all settings", "GET", f"{API_PREFIX}/settings",
                 skip_if_no_token=True)
        self.test("Get settings for service", "GET",
                 f"{API_PREFIX}/settings/api",
                 skip_if_no_token=True)
        if self.env_uuid:
            self.test("Get settings for service/env", "GET",
                     f"{API_PREFIX}/settings/api/{self.env_uuid}",
                     skip_if_no_token=True)
            self.test("Get settings JSON for service", "GET",
                     f"{API_PREFIX}/settings/api/json",
                     skip_if_no_token=True)
            self.test("Get settings JSON for service/env", "GET",
                     f"{API_PREFIX}/settings/api/json/{self.env_uuid}",
                     skip_if_no_token=True)
        print()

        # Users
        self.log(f"{Colors.BOLD}--- Users ---{Colors.RESET}")
        self.test("List all users", "GET", f"{API_PREFIX}/users",
                 skip_if_no_token=True)
        if self.username:
            self.test("Get user by username", "GET",
                     f"{API_PREFIX}/users/{self.username}",
                     skip_if_no_token=True)
        print()

        # Queries (if enabled)
        self.log(f"{Colors.BOLD}--- Queries ---{Colors.RESET}")
        if self.env_uuid:
            self.test("Get all queries", "GET",
                     f"{API_PREFIX}/queries/{self.env_uuid}",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
            self.test("Get all queries (alt endpoint)", "GET",
                     f"{API_PREFIX}/all-queries/{self.env_uuid}",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
        print()

        # Carves (if enabled)
        self.log(f"{Colors.BOLD}--- Carves ---{Colors.RESET}")
        if self.env_uuid:
            self.test("Get carves", "GET",
                     f"{API_PREFIX}/carves/{self.env_uuid}",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
            self.test("List carves", "GET",
                     f"{API_PREFIX}/carves/{self.env_uuid}/list",
                     expected_status=[200, 404],
                     skip_if_no_token=True)
        print()

        # Audit logs (if enabled)
        self.log(f"{Colors.BOLD}--- Audit Logs ---{Colors.RESET}")
        self.test("Get audit logs", "GET", f"{API_PREFIX}/audit-logs",
                 skip_if_no_token=True)
        print()

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary with emojis"""
        total = self.passed + self.failed + self.skipped
        pass_rate = (self.passed / total * 100) if total > 0 else 0

        self.log(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        self.log(f"{Colors.BOLD}📊 Test Summary{Colors.RESET}")
        self.log(f"{Colors.BOLD}{'='*50}{Colors.RESET}\n")

        self.log(f"📈 Total tests:   {total}")
        self.log(f"{Colors.GREEN}✅ Passed:        {self.passed} ({pass_rate:.1f}%){Colors.RESET}")
        self.log(f"{Colors.RED}❌ Failed:        {self.failed}{Colors.RESET}")
        self.log(f"{Colors.YELLOW}⏭️ Skipped:       {self.skipped}{Colors.RESET}")

        if self.failed > 0:
            self.log(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
            self.log(f"{Colors.BOLD}❌ Failed tests:{Colors.RESET}")
            self.log(f"{Colors.BOLD}{'='*50}{Colors.RESET}")
            for result in self.test_results:
                if result['status'] == 'failed':
                    self.log(f"  🔴 {result['name']}", Colors.RED)
                    self.log(f"     └─ {result['message']}", Colors.RED)

        # Overall result
        self.log(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        if self.failed == 0 and self.passed > 0:
            self.log(f"{Colors.GREEN}{Colors.BOLD}🎉 All tests passed!{Colors.RESET}")
        elif self.failed > 0:
            self.log(f"{Colors.RED}{Colors.BOLD}⚠️  Some tests failed!{Colors.RESET}")
        else:
            self.log(f"{Colors.YELLOW}{Colors.BOLD}⚠️  No tests were run{Colors.RESET}")
        self.log(f"{Colors.BOLD}{'='*50}{Colors.RESET}\n")

        # Exit with appropriate code
        if self.failed > 0:
            sys.exit(1)
        else:
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive API tester for osctrl-api',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('base_url', help='Base URL of the API (e.g., http://localhost:9000)')
    parser.add_argument('--username', '-u', help='Username for authentication')
    parser.add_argument('--password', '-p', help='Password for authentication')
    parser.add_argument('--env', '-e', dest='env_uuid', help='Environment UUID for testing')
    parser.add_argument('--token', '-t', help='Use existing API token instead of logging in')
    parser.add_argument('--skip-auth', action='store_true', help='Skip authentication tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed request/response info')
    parser.add_argument('--insecure', '-k', action='store_true',
                       help='Disable SSL certificate verification')

    args = parser.parse_args()

    tester = APITester(
        base_url=args.base_url,
        token=args.token,
        username=args.username,
        password=args.password,
        env_uuid=args.env_uuid,
        verbose=args.verbose,
        insecure=args.insecure
    )

    tester.run_all_tests(skip_auth=args.skip_auth)


if __name__ == '__main__':
    main()
