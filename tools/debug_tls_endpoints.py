#!/usr/bin/env python3

import argparse
import json
import pathlib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def parse_flags_text(text):
    flags = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("--"):
            continue
        line = line[2:]
        if "=" in line:
            key, value = line.split("=", 1)
            flags[key.strip()] = value.strip()
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            flags[parts[0].strip()] = parts[1].strip()
        else:
            flags[parts[0].strip()] = "true"
    return flags


def read_flags_file(path):
    return parse_flags_text(pathlib.Path(path).read_text())


def normalize_host(host):
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"https://{host.rstrip('/')}"


def join_url(host, endpoint):
    return urllib.parse.urljoin(f"{normalize_host(host)}/", endpoint.lstrip("/"))


def load_secret(path):
    return pathlib.Path(path).read_text().strip()


def pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True)


def dump_message(title, content):
    print(f"\n=== {title} ===")
    print(content)


def make_ssl_context(args, flags):
    if args.insecure:
        return ssl._create_unverified_context()
    cafile = args.ca_file or flags.get("tls_server_certs")
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


def endpoint_map(args, flags):
    return {
        "enroll": args.enroll_endpoint or flags.get("enroll_tls_endpoint"),
        "config": args.config_endpoint or flags.get("config_tls_endpoint"),
        "log": args.log_endpoint or flags.get("logger_tls_endpoint"),
        "read": args.read_endpoint or flags.get("distributed_tls_read_endpoint"),
        "write": args.write_endpoint or flags.get("distributed_tls_write_endpoint"),
    }


def default_log_data(identifier):
    return [
        {
            "severity": 0,
            "filename": "debug_tls_endpoints.py",
            "line": 1,
            "message": "debug log submission",
            "version": "1.0.0",
            "unixTime": 1710000000,
            "calendarTime": "Mon Jul 01 00:00:00 2026 UTC",
            "hostIdentifier": identifier,
            "decorations": {},
        }
    ]


def default_write_queries(args):
    return {args.query_name: json.loads(args.write_result)}


def request_payload(action, args, secret_value):
    if action == "enroll":
        return {
            "enroll_secret": secret_value,
            "host_identifier": args.identifier,
            "platform_type": "linux",
            "host_details": {
                "os_version": {"name": "debug", "platform": "linux", "version": "0"},
                "osquery_info": {"version": "debug"},
                "system_info": {"hostname": args.identifier, "uuid": args.identifier},
                "platform_info": {"vendor": "debug"},
            },
        }
    if action == "config":
        return {"node_key": args.node_key}
    if action == "log":
        data = json.loads(args.log_data) if args.log_data else default_log_data(args.identifier)
        return {"node_key": args.node_key, "log_type": args.log_type, "data": data}
    if action == "read":
        return {"node_key": args.node_key}
    if action == "write":
        return {
            "node_key": args.node_key,
            "queries": default_write_queries(args),
            "statuses": {args.query_name: args.write_status},
            "messages": {args.query_name: args.write_message},
        }
    raise ValueError(f"unsupported action: {action}")


def send_request(url, payload, context, timeout):
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "osctrl-debug-tls/1.0",
    }
    dump_message("REQUEST", f"POST {url}")
    dump_message("REQUEST HEADERS", pretty_json(headers))
    dump_message("REQUEST BODY", pretty_json(payload))
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            status = response.status
            response_headers = dict(response.headers.items())
            response_body = response.read()
    except urllib.error.HTTPError as err:
        status = err.code
        response_headers = dict(err.headers.items())
        response_body = err.read()
    dump_message("RESPONSE STATUS", str(status))
    dump_message("RESPONSE HEADERS", pretty_json(response_headers))
    try:
        parsed = json.loads(response_body.decode("utf-8"))
        dump_message("RESPONSE BODY", pretty_json(parsed))
    except (UnicodeDecodeError, json.JSONDecodeError):
        dump_message("RESPONSE BODY", response_body.decode("utf-8", errors="replace"))


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Raw TLS endpoint debugger for osctrl/osquery flows."
    )
    parser.add_argument(
        "action",
        choices=["all", "enroll", "config", "log", "read", "write"],
        help="Endpoint flow to exercise.",
    )
    parser.add_argument("--host", help="Base host, for example https://127.0.0.1:9003")
    parser.add_argument("--flags", help="Path to osquery.flags")
    parser.add_argument("--secret", help="Path to osquery.secret")
    parser.add_argument("--ca-file", help="CA bundle path for TLS verification")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--node-key", default="debug-node-key")
    parser.add_argument("--identifier", default="debug-node")
    parser.add_argument("--enroll-endpoint")
    parser.add_argument("--config-endpoint")
    parser.add_argument("--log-endpoint")
    parser.add_argument("--read-endpoint")
    parser.add_argument("--write-endpoint")
    parser.add_argument("--log-type", default="status", choices=["status", "result", "query"])
    parser.add_argument("--log-data", help="Raw JSON for the log data field")
    parser.add_argument("--query-name", default="debug")
    parser.add_argument("--write-result", default='[{"value":"1"}]')
    parser.add_argument("--write-status", type=int, default=0)
    parser.add_argument("--write-message", default="")
    return parser.parse_args(argv)


def validate_args(args, flags, endpoints):
    if not (args.host or flags.get("tls_hostname")):
        raise SystemExit("missing host: pass --host or provide --tls_hostname in --flags")
    needed = ["config", "log", "read", "write"] if args.action == "all" else [args.action]
    for action in needed:
        if not endpoints.get(action):
            raise SystemExit(f"missing endpoint for {action}")
    if args.action == "enroll" and not (args.secret or flags.get("enroll_secret_path")):
        raise SystemExit("enroll needs --secret or --enroll_secret_path in --flags")


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    flags = read_flags_file(args.flags) if args.flags else {}
    endpoints = endpoint_map(args, flags)
    validate_args(args, flags, endpoints)
    host = args.host or flags["tls_hostname"]
    context = make_ssl_context(args, flags)
    secret_path = args.secret or flags.get("enroll_secret_path")
    secret_value = load_secret(secret_path) if secret_path else None

    actions = ["config", "log", "read", "write"] if args.action == "all" else [args.action]
    for action in actions:
        url = join_url(host, endpoints[action])
        payload = request_payload(action, args, secret_value)
        send_request(url, payload, context, args.timeout)


if __name__ == "__main__":
    main()
