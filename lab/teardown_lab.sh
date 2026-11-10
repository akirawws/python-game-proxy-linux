#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly RUN_DIR="${NETSHIELD_LAB_RUN_DIR:-/run/netshield-lab}"

readonly NS_CLIENT="ns-client"
readonly NS_GW="ns-gw"
readonly NS_BACKEND="ns-backend"

readonly VETH_CLIENT="veth-cl"
readonly VETH_GW_CLIENT="veth-gw-cl"
readonly VETH_GW_BACKEND="veth-gw-be"
readonly VETH_BACKEND="veth-be"

QUIET=0

usage() {
    cat <<EOF
Назначение:
  Останавливает сервисы backend и удаляет лабораторный стенд NetShield.

Использование:
  sudo bash lab/teardown_lab.sh [--quiet]

Опции:
  --quiet    Не выводить сообщения об удалении.
  -h, --help Показать эту справку.
EOF
}

log() {
    if (( QUIET == 0 )); then
        printf '[netshield-lab] %s\n' "$*"
    fi
}

die() {
    printf '[netshield-lab] ОШИБКА: %s\n' "$*" >&2
    exit 1
}

while (( $# > 0 )); do
    case "$1" in
        --quiet)
            QUIET=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "неизвестный аргумент: $1 (см. --help)"
            ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "стенд существует только на Linux"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root: sudo bash lab/teardown_lab.sh"
[[ -n "$RUN_DIR" && "$RUN_DIR" != "/" ]] || die "некорректный NETSHIELD_LAB_RUN_DIR"
command -v ip >/dev/null 2>&1 || die "не найден ip (установите iproute2)"

if [[ -f "$RUN_DIR/backend.pid" ]]; then
    backend_pid="$(cat "$RUN_DIR/backend.pid" 2>/dev/null || true)"
    if [[ -n "$backend_pid" ]] && kill -0 "$backend_pid" 2>/dev/null; then
        log "остановка backend (pid $backend_pid)"
        kill "$backend_pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$backend_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$backend_pid" 2>/dev/null || true
    fi
fi

namespace_exists() {
    ip netns list | awk '{print $1}' | grep -qx "$1"
}

for namespace in "$NS_BACKEND" "$NS_GW" "$NS_CLIENT"; do
    if namespace_exists "$namespace"; then
        pids="$(ip netns pids "$namespace" 2>/dev/null || true)"
        if [[ -n "$pids" ]]; then
            kill $pids 2>/dev/null || true
        fi
        log "удаление $namespace"
        ip netns delete "$namespace" || true
    fi
done

for veth in "$VETH_CLIENT" "$VETH_GW_CLIENT" "$VETH_GW_BACKEND" "$VETH_BACKEND"; do
    if ip link show dev "$veth" >/dev/null 2>&1; then
        ip link delete "$veth" || true
    fi
done

if [[ -d "$RUN_DIR" ]]; then
    rm -rf "$RUN_DIR"
fi

log "стенд остановлен"
