#!/usr/bin/env python3
"""Генератор тестового TCP/UDP-трафика для лабораторного стенда NetShield."""

from __future__ import annotations

import argparse
import socket
import sys
import time


def run_tcp(args: argparse.Namespace) -> int:
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: netshield-lab\r\n"
        b"Connection: close\r\n\r\n"
    )
    ok = 0
    failed = 0

    for index in range(args.count):
        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
                sock.sendall(payload)
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            if b"200 OK" in response:
                ok += 1
            else:
                failed += 1
                print(
                    f"tcp {index + 1}/{args.count}: неожиданный ответ {response[:80]!r}",
                    file=sys.stderr,
                )
        except OSError as exc:
            failed += 1
            print(f"tcp {index + 1}/{args.count}: {exc}", file=sys.stderr)

        if args.interval > 0:
            time.sleep(args.interval)

    print(f"tcp: ok={ok} fail={failed}")
    return 0 if failed == 0 else 1


def run_udp(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    ok = 0
    failed = 0
    started = time.monotonic()

    for index in range(args.count):
        try:
            sock.sendto(args.payload.encode("utf-8"), (args.host, args.port))
            response, _ = sock.recvfrom(2048)
            if response.startswith(b"pong:"):
                ok += 1
            else:
                failed += 1
                print(
                    f"udp {index + 1}/{args.count}: неожиданный ответ {response[:80]!r}",
                    file=sys.stderr,
                )
        except OSError as exc:
            failed += 1
            print(f"udp {index + 1}/{args.count}: {exc}", file=sys.stderr)

        if args.rate > 0:
            target = started + (index + 1) / args.rate
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)

    print(f"udp: ok={ok} fail={failed}")
    return 0 if failed == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP/UDP-генератор для проверки стенда NetShield"
    )
    parser.add_argument("--mode", choices=("tcp", "udp"), required=True)
    parser.add_argument("--host", required=True, help="целевой IPv4-адрес")
    parser.add_argument("--port", type=int, default=None, help="целевой порт")
    parser.add_argument("--count", type=int, default=10, help="число запросов или пакетов")
    parser.add_argument("--timeout", type=float, default=3.0, help="таймаут операции, сек")
    parser.add_argument("--interval", type=float, default=0.0, help="пауза между TCP-запросами")
    parser.add_argument("--rate", type=float, default=0.0, help="частота UDP-пакетов в секунду")
    parser.add_argument("--payload", default="ping", help="полезная нагрузка UDP")
    args = parser.parse_args()

    if args.port is None:
        args.port = 8080 if args.mode == "tcp" else 9090
    if args.count < 1:
        parser.error("--count должен быть больше 0")
    if args.timeout <= 0:
        parser.error("--timeout должен быть больше 0")
    if args.rate < 0:
        parser.error("--rate не может быть отрицательным")
    return args


def main() -> int:
    args = parse_args()
    if args.mode == "tcp":
        return run_tcp(args)
    return run_udp(args)


if __name__ == "__main__":
    raise SystemExit(main())
