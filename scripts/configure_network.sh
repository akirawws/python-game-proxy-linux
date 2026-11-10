#!/usr/bin/env bash
# configure_network.sh — маршрутизация и IP forwarding
set -euo pipefail

LAN_IFACE=""
WAN_IFACE=""
LAN_CIDR=""
CHECK=0
NO_PERSIST=0

while (( $# > 0 )); do
    case "$1" in
        --lan-iface) LAN_IFACE="$2"; shift 2 ;;
        --wan-iface) WAN_IFACE="$2"; shift 2 ;;
        --lan-cidr) LAN_CIDR="$2"; shift 2 ;;
        --check) CHECK=1; shift ;;
        --no-persist) NO_PERSIST=1; shift ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

log() { printf '[netshield-network] %s\n' "$*"; }
die() { printf '[netshield-network] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root"
command -v sysctl >/dev/null 2>&1 || die "не найден sysctl"
command -v nft >/dev/null 2>&1 || die "не найден nft"

# 1. Включаем IP forwarding
log "Включение IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# 2. rp_filter и syncookies для базовой защиты
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true

# 3. Если заданы интерфейсы — настраиваем пересылку и NAT
if [[ -n "$LAN_IFACE" && -n "$WAN_IFACE" ]]; then
    log "Настройка пересылки трафика: $LAN_IFACE <-> $WAN_IFACE"

    nft add table inet netshield 2>/dev/null || true

    # Базовая цепочка forward: разрешаем установленные соединения, novas — по правилам
    nft add chain inet netshield forward '{ type filter hook forward priority 0; policy drop; }' 2>/dev/null || true
    nft add chain inet netshield input '{ type filter hook input priority 0; policy drop; }' 2>/dev/null || true
    nft add chain inet netshield output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

    # Разрешаем established/related
    nft add rule inet netshield forward ct state established,related accept 2>/dev/null || true

    # Пересылка из LAN в WAN и обратно
    nft add rule inet netshield forward iifname "$LAN_IFACE" oifname "$WAN_IFACE" ip saddr "$LAN_CIDR" accept 2>/dev/null || true
    nft add rule inet netshield forward iifname "$WAN_IFACE" oifname "$LAN_IFACE" ip daddr "$LAN_CIDR" ct state established,related accept 2>/dev/null || true

    # NAT (masquerade) для исходящего трафика из LAN
    nft add chain inet netshield postrouting '{ type nat hook postrouting priority 100; policy accept; }' 2>/dev/null || true
    nft add rule inet netshield postrouting oifname "$WAN_IFACE" ip saddr "$LAN_CIDR" masquerade 2>/dev/null || true

    log "Маршрутизация и NAT настроены."
fi

# 4. Проверка
if (( CHECK )); then
    log "Проверка настроек сети..."
    echo "IP forwarding (ipv4): $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'n/a')"
    echo "IP forwarding (ipv6): $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 'n/a')"
    nft list ruleset 2>/dev/null || true
fi

if (( ! NO_PERSIST )); then
    log "Сохранение правил nftables..."
    nft list ruleset > /etc/nftables.conf 2>/dev/null || true
fi

log "Готово."
