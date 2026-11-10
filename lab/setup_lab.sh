#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly RUN_DIR="${NETSHIELD_LAB_RUN_DIR:-/run/netshield-lab}"

readonly NS_CLIENT="ns-client"
readonly NS_GW="ns-gw"
readonly NS_BACKEND="ns-backend"

readonly VETH_CLIENT="veth-cl"
readonly VETH_GW_CLIENT="veth-gw-cl"
readonly VETH_GW_BACKEND="veth-gw-be"
readonly VETH_BACKEND="veth-be"

readonly CLIENT_IP="10.10.0.2"
readonly CLIENT_CIDR="10.10.0.0/24"
readonly GW_CLIENT_IP="10.10.0.1"
readonly BACKEND_IP="10.20.0.2"
readonly GW_BACKEND_IP="10.20.0.1"

HTTP_PORT="${HTTP_PORT:-8080}"
UDP_PORT="${UDP_PORT:-9090}"
FORCE=0
VERIFY=1

usage() {
    cat <<EOF
Назначение:
  Создаёт изолированный лабораторный стенд NetShield на network namespaces:
  ns-client -> ns-gw (NAT, forwarding) -> ns-backend (Web + UDP-сервисы).

Использование:
  sudo bash lab/setup_lab.sh [опции]

Опции:
  --force               Пересоздать стенд, если он уже существует.
  --no-verify           Не выполнять автоматическую проверку TCP/UDP.
  --http-port <port>    TCP-порт Web-сервиса backend (по умолчанию 8080).
  --udp-port <port>     UDP-порт игрового сервиса backend (по умолчанию 9090).
  -h, --help            Показать эту справку.

Переменные окружения:
  HTTP_PORT, UDP_PORT, NETSHIELD_LAB_RUN_DIR.

Очистка:
  sudo bash lab/teardown_lab.sh
EOF
}

log() {
    printf '[netshield-lab] %s\n' "$*"
}

warn() {
    printf '[netshield-lab] ВНИМАНИЕ: %s\n' "$*" >&2
}

die() {
    printf '[netshield-lab] ОШИБКА: %s\n' "$*" >&2
    exit 1
}

while (( $# > 0 )); do
    case "$1" in
        --force)
            FORCE=1
            shift
            ;;
        --no-verify)
            VERIFY=0
            shift
            ;;
        --http-port)
            [[ $# -ge 2 ]] || die "для --http-port требуется значение"
            HTTP_PORT="$2"
            shift 2
            ;;
        --udp-port)
            [[ $# -ge 2 ]] || die "для --udp-port требуется значение"
            UDP_PORT="$2"
            shift 2
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

for port in "$HTTP_PORT" "$UDP_PORT"; do
    [[ "$port" =~ ^[0-9]+$ ]] || die "порт должен быть числом: $port"
    (( port >= 1 && port <= 65535 )) || die "порт вне диапазона 1-65535: $port"
done
[[ "$HTTP_PORT" != "$UDP_PORT" ]] || die "порты HTTP и UDP должны различаться"

[[ "$(uname -s)" == "Linux" ]] || die "стенд создаётся только на Linux"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root: sudo bash lab/setup_lab.sh ..."
command -v ip >/dev/null 2>&1 || die "не найден ip (установите iproute2)"
command -v python3 >/dev/null 2>&1 || die "не найден python3"
command -v sysctl >/dev/null 2>&1 || die "не найден sysctl (установите procps)"
command -v nft >/dev/null 2>&1 || die "не найден nft (установите nftables)"

namespace_exists() {
    ip netns list | awk '{print $1}' | grep -qx "$1"
}

cleanup_stale_veths() {
    local veth
    for veth in "$VETH_CLIENT" "$VETH_GW_CLIENT" "$VETH_GW_BACKEND" "$VETH_BACKEND"; do
        if ip link show dev "$veth" >/dev/null 2>&1; then
            ip link delete "$veth" || true
        fi
    done
}

if namespace_exists "$NS_CLIENT" || namespace_exists "$NS_GW" || namespace_exists "$NS_BACKEND"; then
    if (( FORCE )); then
        log "пересоздание существующего стенда"
        bash "$SCRIPT_DIR/teardown_lab.sh" --quiet
    else
        die "стенд уже существует. Используйте --force для пересоздания или bash lab/teardown_lab.sh"
    fi
fi

cleanup_stale_veths
install -d -m 0700 "$RUN_DIR"

log "создание network namespaces"
ip netns add "$NS_CLIENT"
ip netns add "$NS_GW"
ip netns add "$NS_BACKEND"

log "создание veth-линков"
ip link add "$VETH_CLIENT" type veth peer name "$VETH_GW_CLIENT"
ip link set "$VETH_GW_CLIENT" netns "$NS_GW"
ip link set "$VETH_CLIENT" netns "$NS_CLIENT"

ip link add "$VETH_BACKEND" type veth peer name "$VETH_GW_BACKEND"
ip link set "$VETH_GW_BACKEND" netns "$NS_GW"
ip link set "$VETH_BACKEND" netns "$NS_BACKEND"

for namespace in "$NS_CLIENT" "$NS_GW" "$NS_BACKEND"; do
    ip -n "$namespace" link set lo up
done

log "настройка адресов и маршрутов"
ip -n "$NS_CLIENT" addr add "$CLIENT_IP/24" dev "$VETH_CLIENT"
ip -n "$NS_CLIENT" link set "$VETH_CLIENT" up
ip -n "$NS_CLIENT" route add default via "$GW_CLIENT_IP"

ip -n "$NS_GW" addr add "$GW_CLIENT_IP/24" dev "$VETH_GW_CLIENT"
ip -n "$NS_GW" addr add "$GW_BACKEND_IP/24" dev "$VETH_GW_BACKEND"
ip -n "$NS_GW" link set "$VETH_GW_CLIENT" up
ip -n "$NS_GW" link set "$VETH_GW_BACKEND" up

ip -n "$NS_BACKEND" addr add "$BACKEND_IP/24" dev "$VETH_BACKEND"
ip -n "$NS_BACKEND" link set "$VETH_BACKEND" up
ip -n "$NS_BACKEND" route add default via "$GW_BACKEND_IP"

log "настройка forwarding и NAT на шлюзе"
ip netns exec "$NS_GW" bash "$REPO_ROOT/scripts/configure_network.sh" \
    --lan-iface "$VETH_GW_CLIENT" \
    --wan-iface "$VETH_GW_BACKEND" \
    --lan-cidr "$CLIENT_CIDR" \
    --no-persist

log "запуск сервисов backend"
ip netns exec "$NS_BACKEND" python3 "$SCRIPT_DIR/backend_services.py" \
    --host 0.0.0.0 \
    --http-port "$HTTP_PORT" \
    --udp-port "$UDP_PORT" \
    >"$RUN_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
printf '%s\n' "$BACKEND_PID" > "$RUN_DIR/backend.pid"

ready=0
for _ in $(seq 1 100); do
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        warn "процесс backend завершился. Лог: $RUN_DIR/backend.log"
        tail -n 50 "$RUN_DIR/backend.log" >&2 || true
        die "не удалось запустить сервисы backend"
    fi
    if ip netns exec "$NS_BACKEND" python3 -c \
        'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()' \
        "$HTTP_PORT" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done

if (( ready == 0 )); then
    warn "backend не открыл TCP-порт $HTTP_PORT за отведённое время"
    tail -n 50 "$RUN_DIR/backend.log" >&2 || true
    die "проверьте лог $RUN_DIR/backend.log"
fi

verify_lab() {
    ip netns exec "$NS_CLIENT" python3 - "$BACKEND_IP" "$HTTP_PORT" "$UDP_PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
http_port = int(sys.argv[2])
udp_port = int(sys.argv[3])

with socket.create_connection((host, http_port), timeout=5) as sock:
    sock.sendall(
        b"GET / HTTP/1.1\r\nHost: netshield-lab\r\nConnection: close\r\n\r\n"
    )
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

if b"200 OK" not in response:
    raise SystemExit(f"TCP: неожиданный ответ: {response[:120]!r}")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(b"ping", (host, udp_port))
reply, _ = udp.recvfrom(2048)

if not reply.startswith(b"pong:"):
    raise SystemExit(f"UDP: неожиданный ответ: {reply!r}")

print(f"проверка пройдена: TCP {host}:{http_port}, UDP {host}:{udp_port}")
PY
}

if (( VERIFY )); then
    log "проверка прохождения TCP/UDP-трафика через шлюз"
    if ! verify_lab; then
        warn "автоматическая проверка не пройдена. Лог backend: $RUN_DIR/backend.log"
        die "стенд создан, но трафик не проходит. Для очистки: sudo bash lab/teardown_lab.sh"
    fi
else
    log "автоматическая проверка пропущена (--no-verify)"
fi

cat <<EOF

Стенд NetShield готов.

  ns-client   $VETH_CLIENT        $CLIENT_IP/24      default via $GW_CLIENT_IP
  ns-gw       $VETH_GW_CLIENT   $GW_CLIENT_IP/24
              $VETH_GW_BACKEND   $GW_BACKEND_IP/24   NAT для $CLIENT_CIDR
  ns-backend  $VETH_BACKEND     $BACKEND_IP/24      default via $GW_BACKEND_IP

  backend: HTTP 0.0.0.0:$HTTP_PORT, UDP 0.0.0.0:$UDP_PORT
  лог:     $RUN_DIR/backend.log

Проверка вручную:
  sudo ip netns exec $NS_CLIENT python3 $SCRIPT_DIR/client_traffic.py \\
      --mode tcp --host $BACKEND_IP --port $HTTP_PORT --count 5
  sudo ip netns exec $NS_CLIENT python3 $SCRIPT_DIR/client_traffic.py \\
      --mode udp --host $BACKEND_IP --port $UDP_PORT --count 20 --rate 10
  sudo ip netns exec $NS_GW bash $REPO_ROOT/scripts/configure_network.sh \\
      --lan-iface $VETH_GW_CLIENT --wan-iface $VETH_GW_BACKEND \\
      --lan-cidr $CLIENT_CIDR --check

Очистка:
  sudo bash $SCRIPT_DIR/teardown_lab.sh
EOF
