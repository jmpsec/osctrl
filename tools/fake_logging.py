#!/usr/bin/env python
# coding=utf-8
#
# Script to simulate HTTP logging services (Graylog, Splunk...) for osctrl
#
# Usage: python fake_logging.py port
#

_NAME = "FakeServerLogging"
_BIND = "0.0.0.0"
_PARAMS = 2

_UTF = 'utf-8'

import http.server
import socketserver
import sys
import time
import json


class FakeServer(http.server.SimpleHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write(bytes("{'text':'Success','code':0}", _UTF))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_headers()
        self.wfile.write(bytes("{'text':'Success','code':0}", _UTF))
        print(
            "-----------------------------------Headers-----------------------------------------"
        )
        print(str(self.headers))
        print(
            "------------------------------------Body-------------------------------------------"
        )
        print(json.dumps(json.loads(post_data.decode(_UTF)), indent=4))
        print(
            "-----------------------------------------------------------------------------------"
        )


if __name__ == '__main__':
    if len(sys.argv) < _PARAMS:
        print
        print('Usage: ' + sys.argv[0] + ' port')
        exit(1)

    _port = int(sys.argv[1])

    httpd = socketserver.TCPServer((_BIND, _port), FakeServer)
    print(time.asctime(), _NAME + ' UP - %s:%s' % (_BIND, _port))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), _NAME + ' DOWN - %s:%s' % (_BIND, _port))
