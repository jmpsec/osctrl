# osctrl toolset

<p align="center">
  <img alt="osctrl" src="../logo.png" width="300" />
  <p align="center">
    Fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrl/blob/main/LICENSE">
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

Development, migration, load-testing, and packaging helpers used by the osctrl project. Run commands from the repository root unless a section says otherwise.

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

## fake_news_go

Console-native load harness for `osctrl-tls` and `osctrl-api`.

- `steady` mode keeps a fixed load running until interrupted with `Ctrl+C`, `q`, or `Q`
- `sweep` mode ramps node count by stage and stops on the first threshold breach, or exits early with `Ctrl+C`, `q`, or `Q`
- `dashboard` display mode renders a dense `termui` terminal dashboard
- writes `fake_news_report.json` after sweep completion or steady shutdown
- uses `fake_news_state.json` as the default persisted node-state file
- can auto-discover environment UUIDs and enroll secrets from `osctrl-api` with `--discover-envs`
- simulates distributed-query write results internally, without shelling out to `osqueryi`

Quick example:

```shell
$ go run ./tools/fake_news_go --tls-url http://localhost:9000 --env <env-uuid> --secret <secret> --display-mode dashboard
```

Automatic discovery from `osctrl-api`:

```shell
$ go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --api-url http://localhost:9002 \
  --api-username admin \
  --api-password admin \
  --discover-envs \
  --display-mode dashboard
```

Mixed TLS + API sweep:

```shell
$ go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --api-url http://localhost:9002 \
  --api-username admin \
  --api-password admin \
  --env <env-uuid> \
  --secret <secret> \
  --mode sweep \
  --display-mode dashboard
```

Helper targets from `tools/fake_news_go`:

```shell
$ make -C tools/fake_news_go dashboard ENV_UUID=<env-uuid> SECRET=<secret>
$ make -C tools/fake_news_go dashboard DISCOVER_ENVS=1 API_URL=http://localhost:9002 API_USERNAME=admin API_PASSWORD=admin
$ make -C tools/fake_news_go sweep ENV_UUID=<env-uuid> SECRET=<secret>
```

See [tools/fake_news_go/README.md](./fake_news_go/README.md) for details.

## json2yaml-config

Go tool to convert old pre-0.5.0 JSON configuration into the YAML format used by `osctrl-tls` and `osctrl-api`. The converter accepts the legacy service, database, Redis, JWT, SAML, logger, and carver files, but only emits current TLS or API service configuration.

```shell
# Convert an old TLS configuration with graylog logger and S3 carver
$ go run ./tools/json2yaml-config -service tls \
    -config config/tls.json \
    -db config/db.json \
    -redis config/redis.json \
    -logger config/graylog.json \
    -carver config/carver_tls.json \
    -output tls.yml

# Convert an old API configuration with SAML and print to stdout
$ go run ./tools/json2yaml-config -service api \
    -config config/api.json \
    -db config/db.json \
    -redis config/redis.json \
    -jwt config/jwt.json \
    -saml config/saml.json \
    -output -
```

**Options:**

- `-service`: Service to convert: `tls` or `api`. Required.
- `-config`: Path to the old `tls.json` or `api.json`. Required.
- `-db`: Path to the old `db.json` file (optional, defaults are used if omitted)
- `-redis`: Path to the old `redis.json` file (optional, defaults are used if omitted)
- `-jwt`: Path to the old `jwt.json` file (optional, API only)
- `-saml`: Path to the old `saml.json` file (optional, API only)
- `-logger`: Path to the old logger JSON file, keyed by logger type: `graylog`, `splunk`, `elastic`, `logstash`, `kinesis`, `s3` or `kafka` (optional)
- `-carver`: Path to the old S3 carver JSON file (optional)
- `-output`: Path to write the YAML output to (default: `<service>.yml`, use `-` for stdout)

Fields that did not exist in the old JSON configuration (`osquery`, `osctrld`, TLS termination, debug, OIDC...) are filled with the same defaults as the sample files in `deploy/config/`. Review the generated file before using it, in particular `auditLog` (emitted as `false` since the option did not exist pre 0.5.0) and the `osquery` section.

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
  ./tools/build-osctrl-deb.sh -i osquery_5.23.1-1.linux.amd64.deb -o osquery-osctrl_5.23.1-1_amd64.deb

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
  ./tools/build-osctrl-pkg.sh -i osquery_5.23.1.pkg -o osquery-osctrl_5.23.1.pkg
```
