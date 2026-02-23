# osctrl toolset

<p align="center">
  <img alt="osctrl" src="../logo.png" width="300" />
  <p align="center">
    Fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrl/blob/master/LICENSE">
      <img alt="Software License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square&fuckgithubcache=1">
    </a>
    <a href="https://github.com/jmpsec/osctrl">
      <img alt="Build Status" src="https://github.com/jmpsec/osctrl/actions/workflows/build_and_test_main_merge.yml/badge.svg?branch=main&fuckgithubcache=1">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrl">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrl?style=flat-square&fuckgithubcache=1">
    </a>
  </p>
</p>

Random collection of tools/scripts that all have been used at some point during the development of osctrl

## api_tester.py

Comprehensive Python3 test suite for the `osctrl-api` service. Tests all API endpoints systematically and provides detailed pass/fail reporting. Useful for regression testing after making changes to the API.

**Basic usage:**

```shell
# With login credentials
$ python3 api_tester.py http://localhost:9002 --username admin --password admin --env <env-uuid>

# With existing token
$ python3 api_tester.py http://localhost:9002 --token <api-token> --env <env-uuid>

# Skip authentication tests
$ python3 api_tester.py http://localhost:9002 --skip-auth

# Verbose output
$ python3 api_tester.py http://localhost:9002 --token <token> --env <env-uuid> --verbose

# Disable SSL verification (for self-signed certs)
$ python3 api_tester.py https://api.example.com --token <token> --env <env-uuid> --insecure
```

**Options:**

- `--username, -u`: Username for authentication
- `--password, -p`: Password for authentication
- `--env, -e`: Environment UUID for testing (required for most tests)
- `--token, -t`: Use existing API token instead of logging in
- `--skip-auth`: Skip authentication tests
- `--verbose, -v`: Show detailed request/response information
- `--insecure, -k`: Disable SSL certificate verification

The script tests all API endpoints including:

- Health checks and status endpoints
- Authentication (login)
- Environments, platforms, nodes
- Tags, settings, users
- Queries and carves (if enabled)
- Audit logs (if enabled)

It requires to install [requests](https://pypi.org/project/requests/) with `pip install requests`.

## fake_logging.py

Script to simulate HTTP logging services (Graylog, Splunk...) for osctrl and check if logs are being sent. It is just an HTTP catchall service.

```shell
$ python3 fake_logging.py 1234
```

## fake_news.py

Script to simulate load for osctrl. It can effectively simulate thousands of osquery nodes, generating fake status and result logs, generate results for on-demand queries and it re-enrolls nodes if they have been removed.

```shell
$ python3 fake_news.py -h
usage: fake_news.py [-h] [--secret SECRET] [--url URL] [--nodes NODES] [--status STATUS] [--result RESULT] [--config CONFIG] [--query QUERY] [--read [READ]] [--write [WRITE]] [--verbose]

Script to simulate load for osctrl

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -u URL     URL for osctrl-tls used to enroll nodes (default: http://localhost:9000/)
  --nodes NODES, -n NODES
                        Number of random nodes to simulate (default: 5)
  --status STATUS, -S STATUS
                        Interval in seconds for status requests to osctrl (default: 60)
  --result RESULT, -R RESULT
                        Interval in seconds for result requests to osctrl (default: 60)
  --config CONFIG, -c CONFIG
                        Interval in seconds for config requests to osctrl (default: 45)
  --query QUERY, -q QUERY
                        Interval in seconds for query requests to osctrl (default: 30)
  --read [READ], -r [READ]
                        JSON file to read nodes from
  --write [WRITE], -w [WRITE]
                        JSON file to write nodes to
  --verbose, -v         Enable verbose output (default: False)

required arguments:
  --secret SECRET, -s SECRET
                        Secret to enroll nodes for osctrl-tls (default: None)
```

It requires to install [requests](https://pypi.org/project/requests/)  with `pip install requests`.

## build-osctrl-deb.sh

Script to repack the osquery DEB package with the osctrl configuration files to be used with the `osctrl-tls` service. It is recommended to execute as root to avoid permission issues with the `tar` command and the existing permissions of the osquery DEB package.

```shell
$ ./build-osctrl-deb.sh -h

Usage: ./tools/build-osctrl-deb.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...

Options:
  -h          Show this help message and exit
  -c CERT     Path to the osquery certificate file
  -s SECRET   Path to the osquery secret file (default: osquery.secret)
  -f FLAGS    Path to the osquery flags file (default: osquery.flags)
  -i DEB      Path to the osquery DEB file. Required.
  -o DEB      Path to the osctrl DEB file. Required.
  -x          Clear the temporary directory after the process
  -v          Enable verbose mode with 'set -x'

Example:
  ./tools/build-osctrl-deb.sh -i osquery_5.21.0-1.linux.amd64.deb -o osquery-osctrl_5.21.0-1_amd64.deb

```

## build-osctrl-pkg.sh

Script to repack the osquery PKG package with the osctrl configuration files to be used with the `osctrl-tls` service.

```shell
$ ./build-osctrl-pkg.sh -h

Usage: ./build-osctrl-pkg.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...

Options:
  -h          Show this help message and exit
  -n NAME     Name to use for the package (default: osctrl)
  -V VERSION  Version to use for the package (default: 1.0)
  -c CERT     Path to the osquery certificate file
  -s SECRET   Path to the osquery secret file (default: osquery.secret)
  -f FLAGS    Path to the osquery flags file (default: osquery.flags)
  -i PKG      Path to the osquery PKG file. Required.
  -o PKG      Path to the osctrl PKG file. Required.
  -k          Generate a PKG without osquery. Only osctrl files.
  -x          Clear the temporary directory after the process
  -v          Enable verbose mode with 'set -x'

Example:
  ./build-osctrl-pkg.sh -i osquery_5.21.0.pkg -o osquery-osctrl_5.21.0.pkg
```
