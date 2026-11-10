#!/usr/bin/env python3
"""Тестовые сервисы backend для лабораторного стенда NetShield."""

from __future__ import annotations

import argparse
import signal
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WebHandler(BaseHTTPRequestHandler):
    server_version = "NetShieldLabWeb/1.0"

    def do_GET(self) -> None:
        body = b"NetShield lab backend OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 0:
            self.rfile.read(length)
        self.do_GET()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[http] %s %s\n" % (self.address_string(), fmt % args))
        sys.stderr.flush()


class GameHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(b"pong:" + data, self.client_address)


class ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP и UDP-сервисы для лабораторного стенда NetShield"
    )
    parser.add_argument("--host", default="0.0.0.0", help="адрес прослушивания")
    parser.add_argument("--http-port", type=int, default=8080, help="TCP-порт Web-сервиса")
    parser.add_argument("--udp-port", type=int, default=9090, help="UDP-порт игрового сервиса")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    http_server = ThreadingHTTPServer((args.host, args.http_port), WebHandler)
    udp_server = ThreadingUDPServer((args.host, args.udp_port), GameHandler)

    stop = threading.Event()

    def shutdown(signum, frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    threads = [
        threading.Thread(target=http_server.serve_forever, name="http", daemon=True),
        threading.Thread(target=udp_server.serve_forever, name="udp", daemon=True),
    ]
    for thread in threads:
        thread.start()

    print(
        f"backend ready: http://{args.host}:{args.http_port}/ "
        f"udp://{args.host}:{args.udp_port}",
        flush=True,
    )

    while not stop.wait(0.5):
        pass

    http_server.shutdown()
    udp_server.shutdown()
    http_server.server_close()
    udp_server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
