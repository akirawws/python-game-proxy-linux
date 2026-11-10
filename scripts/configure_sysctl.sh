#!/usr/bin/env bash
# configure_sysctl.sh — настройка параметров ядра Linux для шлюза
set -e

echo "Настройка sysctl параметров..."

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1

echo "Готово."
