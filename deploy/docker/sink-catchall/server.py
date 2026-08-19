#!/usr/bin/env python3
"""
Catch-all log sink server for the osctrl dev environment.

Listens on:
  - HTTP :8080  — logs every request method, path, headers, and body to
    stdout. Acts as a Splunk HEC, Graylog GELF, Logstash HTTP, or
    Elastic endpoint for testing log sinks.
  - TCP  :8081  — logs every received line to stdout. Acts as a
    Logstash TCP input.
  - UDP  :8082  — logs every received datagram to stdout. Acts as a
    Logstash UDP input.

All three listeners run concurrently in threads. Every received payload
is printed with a prefix identifying the protocol so you can tell which
sink type sent it when testing multiple at once.

Usage in docker-compose-dev.yml:
  osctrl-sink-catchall:
    image: python:3-slim
    command: python3 /opt/sink/server.py
    volumes:
      - ./deploy/docker/sink-catchall/server.py:/opt/sink/server.py:ro
    ports:
      - 127.0.0.1:8080:8080
      - 127.0.0.1:8081:8081
      - 127.0.0.1:8082:8082

Then configure a sink in the osctrl UI pointing at:
  - Splunk   → http://osctrl-sink-catchall:8080
  - Graylog  → http://osctrl-sink-catchall:8080
  - Logstash → host=osctrl-sink-catchall port=8081 protocol=tcp
  - Elastic  → host=osctrl-sink-catchall port=8080
"""
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


def log(prefix: str, msg: str) -> None:
    # Truncate very long bodies so the docker logs stay readable.
    if len(msg) > 2000:
        msg = msg[:2000] + f"... ({len(msg)} bytes total)"
    print(f"[{prefix}] {msg}", flush=True)


class CatchAllHTTPHandler(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        log(
            f"HTTP {self.command} {self.path}",
            f"headers={dict(self.headers)} body={body.decode('utf-8', errors='replace')}",
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def log_message(self, fmt, *args):
        # Suppress default stderr access logging; we log our own.
        pass


def run_http():
    server = HTTPServer(("0.0.0.0", 8080), CatchAllHTTPHandler)
    log("HTTP", "listening on :8080 (Splunk/Graylog/Logstash-HTTP/Elastic)")
    server.serve_forever()


def run_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 8081))
    sock.listen(5)
    log("TCP", "listening on :8081 (Logstash TCP)")
    while True:
        conn, addr = sock.accept()
        try:
            data = conn.recv(65536)
            if data:
                log(f"TCP from {addr[0]}:{addr[1]}", data.decode("utf-8", errors="replace"))
        except Exception as e:
            log("TCP", f"error: {e}")
        finally:
            conn.close()


def run_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 8082))
    log("UDP", "listening on :8082 (Logstash UDP)")
    while True:
        data, addr = sock.recvfrom(65536)
        if data:
            log(f"UDP from {addr[0]}:{addr[1]}", data.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    log("SINK", "catch-all sink server starting")
    for fn in (run_http, run_tcp, run_udp):
        t = threading.Thread(target=fn, daemon=True)
        t.start()
    # Block forever; daemon threads keep running.
    threading.Event().wait()
