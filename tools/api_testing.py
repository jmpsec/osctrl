#!/usr/bin/env python
# coding=utf-8
#
# Script to test the osctrl-api
#
# Usage: python api_testing.py "osctrl_url" "api_secret"
#

# Install the Python Requests library:
# `pip install requests`

import sys
import json
import requests  # pylint: disable=import-error

NODES_PATH = "/nodes"
QUERIES_PATH = "/queries"
ENVS_PATH = "/environments"
PLATFORMS_PATH = "/platforms"
TAGS_PATH = "/tags"
SETTINGS_PATH = "/settings"

API_PATH = "/api/v1"

PARAMS = 2


def _post(_url, _data, _headers):  # pylint: disable=inconsistent-return-statements
    try:
        # print('POST ', _url)
        # print('DATA: ', _data)
        response = requests.post(
            url=_url,
            data=json.dumps(_data),
            headers=_headers,
        )

        print(f"HTTP {response.status_code}")

        if response.status_code == 200:  # pylint: disable=no-else-return
            parsed_json = json.loads(response.content)
            # print(json.dumps(parsed_json, indent=2, sort_keys=True))
            return parsed_json
        else:
            print(response.content)

    except requests.exceptions.RequestException as e:
        print("HTTP Request failed")
        print(e)


def _get(_url, _headers):  # pylint: disable=inconsistent-return-statements
    try:
        print("GET ", _url)
        response = requests.get(url=_url, headers=_headers, verify=False)

        print(f"HTTP {response.status_code}")

        return response

    except requests.exceptions.RequestException as e:
        print("HTTP Request failed")
        print(e)


def _process_response(response):
    if response.status_code == 200:
        json_formatted_str = json.dumps(json.loads(response.content), indent=2)
        print(json_formatted_str)
    elif resp.status_code == 404:
        print("No nodes found")
    else:
        print("Returned HTTP " + resp.status_code)
        print(str(response.content))


if __name__ == "__main__":
    if len(sys.argv) < PARAMS:
        print()
        print("Usage: " + sys.argv[0] + ' "url" "token"')
        exit(1)  # pylint: disable=consider-using-sys-exit

    _url = sys.argv[1]
    print("API is in = ", _url)
    _token = sys.argv[2]
    print("Using token = ", _token)

    print()

    headers = {"X-Real-IP": "1.2.3.4", "Authorization": "Bearer " + _token}
    # Nodes ---------------------------------------------------------------
    resp = _get(_url + API_PATH + NODES_PATH, headers)
    _process_response(resp)

    # Queries -------------------------------------------------------------
    resp = _get(_url + API_PATH + QUERIES_PATH, headers)
    _process_response(resp)

    # Platforms -----------------------------------------------------------
    resp = _get(_url + API_PATH + PLATFORMS_PATH, headers)
    _process_response(resp)

    # Environments --------------------------------------------------------
    resp = _get(_url + API_PATH + ENVS_PATH, headers)
    _process_response(resp)

    # Tags ----------------------------------------------------------------
    resp = _get(_url + API_PATH + TAGS_PATH, headers)
    _process_response(resp)

    # Settings ------------------------------------------------------------
    resp = _get(_url + API_PATH + SETTINGS_PATH, headers)
    _process_response(resp)

    print("Done")
