#!/usr/bin/env python
# coding=utf-8
#
# Script to simulate load for osctrl
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --url URL, -u URL     URL for osctrl-tls used to enroll nodes (default: http://localhost:9000/)
#   --nodes NODES, -n NODES
#                         Number of random nodes to simulate (default: 5)
#   --status STATUS, -S STATUS
#                         Interval in seconds for status requests to osctrl (default: 60)
#   --result RESULT, -R RESULT
#                         Interval in seconds for result requests to osctrl (default: 60)
#   --config CONFIG, -c CONFIG
#                         Interval in seconds for config requests to osctrl (default: 45)
#   --query QUERY, -q QUERY
#                         Interval in seconds for query requests to osctrl (default: 30)
#   --read [READ], -r [READ]
#                         JSON file to read nodes from
#   --write [WRITE], -w [WRITE]
#                         JSON file to write nodes to
#   --verbose, -v         Enable verbose output (default: False)

# required arguments:
#   --secret SECRET, -s SECRET
#                         Secret to enroll nodes for osctrl-tls (default: None)

# Install the Python Requests library:
# `pip install requests`

import argparse
import json
import random
import requests
import sys
import subprocess
import time
import threading
import uuid

TLS_URL = "http://localhost:9000/"

TLS_ENROLL = "/enroll"
TLS_LOG = "/log"
TLS_CONFIG = "/config"
TLS_QUERY_READ = "/read"
TLS_QUERY_WRITE = "/write"

LOG_INTERVAL = 60
CONFIG_INTERVAL = 45
QUERY_READ_INTERVAL = 30

UBUNTU14 = "ubuntu14"
UBUNTU16 = "ubuntu16"
UBUNTU18 = "ubuntu18"
CENTOS6 = "centos6"
CENTOS7 = "centos7"
DEBIAN8 = "debian8"
DEBIAN9 = "debian9"
FREEBSD = "freebsd"
DARWIN = "darwin"
WINDOWS = "windows"

PLATFORMS = [
    UBUNTU14, UBUNTU16, UBUNTU18, CENTOS6, CENTOS7, DEBIAN8, DEBIAN9, FREEBSD,
    DARWIN, WINDOWS
]

OSQUERY_VERSIONS = [
    "5.0.1", "4.9.0", "3.3.1", "3.3.2", "5.1.0", "5.3.0", "4.8.2"
]

NODES_JSON = "nodes.json"

OSQUERYI = 'osqueryi'


# returns tuple(status_code, parsed_json)
def _post(_url, _data, _headers, _debug):
    try:
        if _debug:
            print('POST to ', _url)
            print('DATA: ', json.dumps(_data, indent=2, sort_keys=True))
        response = requests.post(url=_url,
                                 data=json.dumps(_data),
                                 headers=_headers,
                                 verify=False)

        if _debug:
            print(
                'HTTP {status_code}'.format(status_code=response.status_code))

        if response.status_code == 200:
            parsed_json = json.loads(response.content)
            if _debug:
                print(json.dumps(parsed_json, indent=2, sort_keys=True))
        return response.status_code, parsed_json

    except requests.exceptions.RequestException as e:
        print('HTTP Request failed')
        if _debug:
            print(e)
        return 0, {}


# returns string
def _gen_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))


# returns string
def _gen_hostname(_platform):
    return _platform.capitalize() + "-" + random.choice(
        ["Prod", "Legacy", "Test", "Dev", "PC"])


# returns Object
def _gen_random_node():
    platform_target = random.choice(PLATFORMS)
    return {
        "target": platform_target,
        "ip": _gen_random_ip(),
        "name": _gen_hostname(platform_target),
        "version": random.choice(OSQUERY_VERSIONS),
        "identifier": str(uuid.uuid4()),
        "key": "",
    }


# return list(Object)
def _gen_random_nodes(_n):
    nodes = []
    for i in range(_n):
        nodes.append(_gen_random_node())
    return nodes


# return Object
def _gen_systeminfo(_name, _uuid):
    return {
        "computer_name": _name,
        "cpu_brand":
        "Intel(R) Core(TM) i7-7920HQ CPU @ 3.10GHz\u0000\u0000\u0000\u0000\u0000\u0000\u0000",
        "cpu_logical_cores": "4",
        "cpu_physical_cores": "4",
        "cpu_subtype": "158",
        "cpu_type": "x86_64",
        "hardware_model": "",
        "hostname": _name,
        "local_hostname": _name,
        "physical_memory": "2095869952",
        "uuid": _uuid
    }


# return Object
def _gen_osqueryinfo(_uuid, _version):
    return {
        "build_distro": "build_distro",
        "build_platform": "build_platform",
        "config_hash": "",
        "config_valid": "0",
        "extensions": "active",
        "instance_id": str(uuid.uuid1()),
        "pid": "11",
        "start_time": "1564800635",
        "uuid": _uuid,
        "version": _version,
        "watcher": "9"
    }


# return Object
def _osversion_ubuntu14():
    return {
        "_id": "14.04",
        "major": "14",
        "minor": "04",
        "name": "Ubuntu",
        "patch": "0",
        "platform": "ubuntu",
        "platform_like": "debian",
        "version": "14.04.5 LTS, Trusty Tahr"
    }


# return Object
def _osversion_ubuntu16():
    return {
        "_id": "16.04",
        "codename": "xenial",
        "major": "16",
        "minor": "04",
        "name": "Ubuntu",
        "patch": "0",
        "platform": "ubuntu",
        "platform_like": "debian",
        "version": "16.04.6 LTS (Xenial Xerus)"
    }


# return Object
def _osversion_ubuntu18():
    return {
        "_id": "18.04",
        "codename": "bionic",
        "major": "18",
        "minor": "04",
        "name": "Ubuntu",
        "patch": "0",
        "platform": "ubuntu",
        "platform_like": "debian",
        "version": "18.04.2 LTS (Bionic Beaver)"
    }


# return Object
def _osversion_centos6():
    return {
        "build": "",
        "major": "6",
        "minor": "10",
        "name": "CentOS",
        "patch": "0",
        "platform": "rhel",
        "platform_like": "rhel",
        "version": "CentOS release 6.10 (Final)"
    }


# return Object
def _osversion_centos7():
    return {
        "_id": "7",
        "build": "",
        "major": "7",
        "minor": "6",
        "name": "CentOS Linux",
        "patch": "1810",
        "platform": "rhel",
        "platform_like": "rhel",
        "version": "CentOS Linux release 7.6.1810 (Core)"
    }


def _osversion_debian8():
    return {
        "_id": "8",
        "major": "8",
        "minor": "0",
        "name": "Debian GNU/Linux",
        "patch": "0",
        "platform": "debian",
        "version": "8 (jessie)"
    }


# return Object
def _osversion_debian9():
    return {
        "_id": "9",
        "major": "9",
        "minor": "0",
        "name": "Debian GNU/Linux",
        "patch": "0",
        "platform": "debian",
        "version": "9 (stretch)"
    }


# return Object
def _osversion_freebsd():
    return {
        "build": "STABLE",
        "major": "11",
        "minor": "3",
        "name": "FreeBSD",
        "patch": "",
        "platform": "freebsd",
        "version": "11.3-STABLE"
    }


def _osversion_darwin():
    return {
        "build": "16A323",
        "major": "10",
        "minor": "14",
        "name": "Mac OS X",
        "patch": "0",
        "platform": "darwin",
        "platform_like": "darwin",
        "version": "10.14"
    }


def _osversion_windows():
    return {
        "build": "17763",
        "codename": "Windows 10 Pro",
        "install_date": "20190119193615.000000-420",
        "major": "10",
        "minor": "0",
        "name": "Microsoft Windows 10 Pro",
        "platform": "windows",
        "platform_like": "windows",
        "version": "10.0.17763"
    }


def _gen_config(_key):
    return {"node_key": _key}


def _gen_queryread(_key):
    return {"node_key": _key}


def _gen_querywrite(_node, _query_name, _result):
    queries = {_query_name: _result}
    statuses = {_query_name: 0}
    messages = {_query_name: ""}
    return {
        "node_key": _node['key'],
        "queries": queries,
        "statuses": statuses,
        "messages": messages
    }


def _gen_log_status(_node):
    status = {
        "hostIdentifier": _node['identifier'],
        "calendarTime": time.ctime(),
        "unixTime": str(int(time.time())),
        "severity": "0",
        "filename": "fake_news.py",
        "line": "255",
        "message": "Sent fake log message to TLS",
        "version": _node['version']
    }
    return {"node_key": _node['key'], "log_type": "status", "data": [status]}


def _gen_log_result(_node):
    result = {
        "name": "uptime",
        "hostIdentifier": _node['identifier'],
        "calendarTime": time.ctime(),
        "unixTime": str(int(time.time())),
        "epoch": 0,
        "counter": 0,
        "numerics": False,
        "decorations": {
            "config_hash": "7155bb2b98162fa5641d340e03a38d0502df34f0",
            "hostname": _node['name'],
            "local_hostname": _node['name'],
            "osquery_md5": "8e2490cb34e32cb33d6326ca30763167",
            "osquery_user": "root",
            "osquery_version": _node['version'],
            "username": "user (console)"
        },
        "columns": {
            "days": "0",
            "hours": "1",
            "minutes": "2",
            "seconds": "3",
            "total_seconds": "123456"
        },
        "action": "added"
    }
    return {"node_key": _node['key'], "log_type": "result", "data": [result]}


def _gen_enroll(_node, _secret):
    selector_osversion = {
        UBUNTU14: _osversion_ubuntu14,
        UBUNTU16: _osversion_ubuntu16,
        UBUNTU18: _osversion_ubuntu18,
        CENTOS6: _osversion_centos6,
        CENTOS7: _osversion_centos7,
        DEBIAN8: _osversion_debian8,
        DEBIAN9: _osversion_debian9,
        FREEBSD: _osversion_freebsd,
        DARWIN: _osversion_darwin,
        WINDOWS: _osversion_windows,
    }
    selector_platform = {
        UBUNTU14: "9",
        UBUNTU16: "9",
        UBUNTU18: "9",
        CENTOS6: "9",
        CENTOS7: "9",
        DEBIAN8: "9",
        DEBIAN9: "9",
        FREEBSD: "37",
        DARWIN: "21",
        WINDOWS: "2",
    }
    _osversion = selector_osversion.get(_node['target'],
                                        lambda: _osversion_ubuntu18)
    _platform = selector_platform.get(_node['target'], lambda: "9")
    return {
        "enroll_secret": _secret,
        "host_identifier": _node['identifier'],
        "platform_type": _platform,
        "host_details": {
            "os_version": _osversion(),
            "osquery_info": _gen_osqueryinfo(_node['identifier'],
                                             _node['version']),
            "system_info": _gen_systeminfo(_node['name'], _node['identifier'])
        }
    }


def _osctrl_log_status(_sleep, _node, _urls, _secret, _verbose):
    while (True):
        start = time.perf_counter()
        headers = {"X-Real-IP": _node['ip']}
        data = _gen_log_status(_node)
        code, resp = _post(_urls['log'], data, headers, _verbose)
        request_time = time.perf_counter() - start
        print('⏰ {0:.0f} ms status from'.format(request_time), _node['name'])
        if code != 200:
            print('HTTP', str(code), 'with', _urls['log'])
        if _verbose:
            print(resp)
        if 'node_invalid' in resp and resp['node_invalid']:
            with lock:
                _node['key'] = _osctrl_enroll(_node, _secret, _urls['enroll'],
                                              _verbose)
        time.sleep(_sleep)


def _osctrl_log_result(_sleep, _node, _urls, _secret, _verbose):
    while (True):
        start = time.perf_counter()
        headers = {"X-Real-IP": _node['ip']}
        data = _gen_log_result(_node)
        code, resp = _post(_urls['log'], data, headers, _verbose)
        request_time = time.perf_counter() - start
        print('⏰ {0:.0f} ms result from'.format(request_time), _node['name'])
        if code != 200:
            print('HTTP', str(code), 'with', _urls['log'])
        if _verbose:
            print(resp)
        if 'node_invalid' in resp and resp['node_invalid']:
            with lock:
                _node['key'] = _osctrl_enroll(_node, _secret, _urls['enroll'],
                                              _verbose)
        time.sleep(_sleep)


def _osctrl_config(_sleep, _node, _urls, _secret, _verbose):
    while (True):
        start = time.perf_counter()
        headers = {"X-Real-IP": _node['ip']}
        data = _gen_log_result(_node)
        code, resp = _post(_urls['config'], data, headers, _verbose)
        request_time = time.perf_counter() - start
        print('⏰ {0:.0f} ms config from'.format(request_time), _node['name'])
        if code != 200:
            print('HTTP', str(code), 'with', _urls['config'])
        if _verbose:
            print(resp)
        if 'node_invalid' in resp and resp['node_invalid']:
            with lock:
                _node['key'] = _osctrl_enroll(_node, _secret, _urls['enroll'],
                                              _verbose)
        time.sleep(_sleep)


def _osctrl_query_read(_sleep, _node, _urls, _secret, _verbose):
    while (True):
        start = time.perf_counter()
        headers = {"X-Real-IP": _node['ip']}
        data = _gen_log_result(_node)
        code, resp = _post(_urls['query'], data, headers, _verbose)
        request_time = time.perf_counter() - start
        print('⏰ {0:.0f} ms query from'.format(request_time), _node['name'])
        if code != 200:
            print('HTTP', str(code), 'with', _urls['query'])
        if _verbose:
            print(resp)
        if 'node_invalid' in resp and resp['node_invalid']:
            with lock:
                _node['key'] = _osctrl_enroll(_node, _secret, _urls['enroll'],
                                              _verbose)
        if 'queries' in resp and resp['queries']:
            for qname, q in resp['queries'].items():
                _osctrl_query_write(_node, qname, q, _urls['write'], _verbose)
        time.sleep(_sleep)


def _osquery_query(_query):
    result = subprocess.run([OSQUERYI, '--json', _query],
                            stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def _osctrl_query_write(_node, _query_name, _query, _url, _verbose):
    start = time.perf_counter()
    headers = {"X-Real-IP": _node['ip']}
    query_result = _osquery_query(_query)
    data = _gen_querywrite(_node, _query_name, query_result)
    code, resp = _post(_url, data, headers, _verbose)
    request_time = time.perf_counter() - start
    print('⏰ {0:.0f} ms write from'.format(request_time), _node['name'])
    if code != 200:
        print('HTTP', str(code), 'with', _urls['write'])
    if _verbose:
        print(resp)


def _osctrl_enroll(_node, _secret, _url, _verbose):
    start = time.perf_counter()
    headers = {"X-Real-IP": _node['ip']}
    data = _gen_enroll(_node, _secret)
    code, resp = _post(_url, data, headers, _verbose)
    request_time = time.perf_counter() - start
    print('⏰ {0:.0f} ms config from'.format(request_time), _node['name'])
    if code != 200:
        print('HTTP', str(code), 'with', _url)
        return _node['key']
    if _verbose:
        print(resp)
    return resp['node_key']


# Parser for command line parameters
parser = argparse.ArgumentParser(
    description='Script to simulate load for osctrl',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)

required = parser.add_argument_group('required arguments')

required.add_argument('--secret',
                      '-s',
                      help='Secret to enroll nodes for osctrl-tls')
parser.add_argument('--url',
                    '-u',
                    default=TLS_URL,
                    help='URL for osctrl-tls used to enroll nodes')
parser.add_argument('--nodes',
                    '-n',
                    type=int,
                    default=5,
                    help='Number of random nodes to simulate')
parser.add_argument('--status',
                    '-S',
                    type=int,
                    default=LOG_INTERVAL,
                    help='Interval in seconds for status requests to osctrl')
parser.add_argument('--result',
                    '-R',
                    type=int,
                    default=LOG_INTERVAL,
                    help='Interval in seconds for result requests to osctrl')
parser.add_argument('--config',
                    '-c',
                    type=int,
                    default=CONFIG_INTERVAL,
                    help='Interval in seconds for config requests to osctrl')
parser.add_argument('--query',
                    '-q',
                    type=int,
                    default=QUERY_READ_INTERVAL,
                    help='Interval in seconds for query requests to osctrl')
parser.add_argument('--read',
                    '-r',
                    nargs='?',
                    default=argparse.SUPPRESS,
                    help='JSON file to read nodes from')
parser.add_argument('--write',
                    '-w',
                    nargs='?',
                    default=argparse.SUPPRESS,
                    help='JSON file to write nodes to')
parser.add_argument('--verbose',
                    '-v',
                    default=False,
                    action="store_true",
                    help='Enable verbose output')

lock = threading.Lock()

if __name__ == '__main__':
    # Hide SSL warnings
    requests.packages.urllib3.disable_warnings()

    # Check if required parameters are provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    # Here we go
    _url = args.url
    print('Using URL', _url)

    _urls = {}
    _urls['enroll'] = _url + TLS_ENROLL
    _urls['log'] = _url + TLS_LOG
    _urls['config'] = _url + TLS_CONFIG
    _urls['query'] = _url + TLS_QUERY_READ
    _urls['write'] = _url + TLS_QUERY_WRITE

    _secret = args.secret
    print('Using secret', _secret)

    # If we are reading nodes from JSON file
    _nodes = []
    if 'read' in args:
        file_read = NODES_JSON
        if args.read is not None:
            file_read = args.read
        print('Reading from JSON', file_read)
        f = open(file_read)
        _nodes = json.load(f)
        f.close()
    else:
        _num_nodes = args.nodes
        print('Generating', _num_nodes, 'nodes')
        _nodes = _gen_random_nodes(_num_nodes)

    if args.verbose:
        print(json.dumps(_nodes, indent=2, sort_keys=True))

    # Enroll nodes and extract node_key and save host_identifier
    for n in _nodes:
        print('Enrolling ' + n['target'] + ' as ' + n['name'])
        n['key'] = _osctrl_enroll(n, _secret, _urls['enroll'], args.verbose)

    # Save nodes to file
    if 'write' in args:
        file_write = NODES_JSON
        if args.write is not None:
            file_write = args.write
        print('Writing to JSON', file_write)
        with open(file_write, 'w') as f:
            json.dump(_nodes, f)

    # Begin concurrent traffic
    threads = []

    for n in _nodes:
        # Status log
        t = threading.Thread(target=_osctrl_log_status,
                             args=(args.status, n, _urls, _secret,
                                   args.verbose))
        t.start()
        threads.append(t)
        # Result log
        t = threading.Thread(target=_osctrl_log_result,
                             args=(args.result, n, _urls, _secret,
                                   args.verbose))
        t.start()
        threads.append(t)
        # Config
        t = threading.Thread(target=_osctrl_config,
                             args=(args.config, n, _urls, _secret,
                                   args.verbose))
        t.start()
        threads.append(t)
        # Query read
        t = threading.Thread(target=_osctrl_query_read,
                             args=(args.query, n, _urls, _secret,
                                   args.verbose))
        t.start()
        threads.append(t)
