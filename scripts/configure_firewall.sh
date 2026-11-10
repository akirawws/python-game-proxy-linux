#!/usr/bin/env bash
# configure_firewall.sh — базовые правила nftables
set -euo pipefail

CHECK=0
FLUSH=0

while (( $# > 0 )); do
    case "$1" in
        --check) CHECK=1; shift ;;
        --flush) FLUSH=1; shift ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

log() { printf '[netshield-firewall] %s\n' "$*"; }
die() { printf '[netshield-firewall] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root"
command -v nft >/dev/null 2>&1 || die "не найден nft"

if (( FLUSH )); then
    log "Очистка правил nftables..."
    nft flush ruleset 2>/dev/null || true
fi

log "Создание базовых таблиц и цепочек nftables..."

nft add table inet netshield 2>/dev/null || true

# Input: разрешаем loopback, established/related, ICMP, SSH (22), DNS (53)
nft add chain inet netshield input '{ type filter hook input priority 0; policy drop; }' 2>/dev/null || true
nft add rule inet netshield input iifname "lo" accept 2>/dev/null || true
nft add rule inet netshield input ct state established,related accept 2>/dev/null || true
nft add rule inet netshield input ip protocol icmp accept 2>/dev/null || true
nft add rule inet netshield input ip6 nexthdr icmpv6 accept 2>/dev/null || true
nft add rule inet netshield input tcp dport 22 accept 2>/dev/null || true
nft add rule inet netshield input udp dport 53 accept 2>/dev/null || true
nft add rule inet netshield input tcp dport 53 accept 2>/dev/null || true
# Логируем и отклоняем всё остальное на вход
nft add rule inet netshield input log prefix "netshield-input-drop: " 2>/dev/null || true
nft add rule inet netshield input drop 2>/dev/null || true

# Forward: базовая цепочка, правила добавляются динамически через Rule Manager
nft add chain inet netshield forward '{ type filter hook forward priority 0; policy drop; }' 2>/dev/null || true
nft add rule inet netshield forward ct state established,related accept 2>/dev/null || true
nft add rule inet netshield forward log prefix "netshield-forward-drop: " 2>/dev/null || true
nft add rule inet netshield forward drop 2>/dev/null || true

# Output: разрешаем всё исходящее
nft add chain inet netshield output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

# Postrouting: NAT
nft add chain inet netshield postrouting '{ type nat hook postrouting priority 100; policy accept; }' 2>/dev/null || true

# Цепочки для динамических правил защиты (используются Rule Manager)
nft add chain inet netshield protect_input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
nft add chain inet netshield protect_forward '{ type filter hook forward priority -10; policy accept; }' 2>/dev/null || true

if (( CHECK )); then
    log "Проверка правил брандмауэра..."
    nft list ruleset
fi

log "Сохранение правил..."
nft list ruleset > /etc/nftables.conf 2>/dev/null || true

log "Готово."
