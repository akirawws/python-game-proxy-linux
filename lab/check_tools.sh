#!/usr/bin/env bash
set -euo pipefail

REQUIRED=(ip nft sysctl python3)
OPTIONAL=(conntrack tcpdump iperf3 pytest curl wrk k6)

missing=0

print_tool() {
    local cmd="$1"
    local requirement="$2"
    local version=""

    if command -v "$cmd" >/dev/null 2>&1; then
        case "$cmd" in
            ip) version="$(ip -V 2>&1 | head -n 1 || true)" ;;
            k6) version="$(k6 version 2>&1 | head -n 1 || true)" ;;
            *) version="$("$cmd" --version 2>&1 | head -n 1 || true)" ;;
        esac
        printf '[ok]   %-12s %s\n' "$cmd" "${version:-установлен}"
    else
        if [[ "$requirement" == "required" ]]; then
            printf '[--]   %-12s не найден (обязателен)\n' "$cmd" >&2
            missing=1
        else
            printf '[--]   %-12s не найден (опционально)\n' "$cmd"
        fi
    fi
}

printf 'NetShield lab: проверка инструментов\n'
printf 'Ядро: %s\n' "$(uname -srm)"
printf 'Дистрибутив: %s\n\n' "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '\"' || printf 'не определён')"

printf 'Обязательные:\n'
for tool in "${REQUIRED[@]}"; do
    print_tool "$tool" required
done

printf '\nОпциональные:\n'
for tool in "${OPTIONAL[@]}"; do
    print_tool "$tool" optional
done

printf '\nПроверка возможностей ядра:\n'
if [[ -e /proc/sys/net/ipv4/ip_forward ]]; then
    printf '[ok]   IPv4 forwarding доступен\n'
else
    printf '[--]   /proc/sys/net/ipv4/ip_forward не найден\n' >&2
    missing=1
fi

if command -v ip >/dev/null 2>&1 && ip netns list >/dev/null 2>&1; then
    printf '[ok]   network namespaces доступны\n'
else
    printf '[--]   network namespaces недоступны (нужен root и поддержка ядра)\n' >&2
    missing=1
fi

printf '\n'
if (( missing )); then
    printf 'Не все обязательные компоненты доступны.\n' >&2
    exit 1
fi

printf 'Все обязательные компоненты доступны.\n'
