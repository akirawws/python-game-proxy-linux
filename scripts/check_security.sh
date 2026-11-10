#!/usr/bin/env bash
# check_security.sh — проверка состояния безопасности шлюза
set -euo pipefail

log() { printf '[netshield-check] %s\n' "$*"; }
die() { printf '[netshield-check] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root"

FAIL=0

check() {
    local name="$1"
    local result="$2"
    local detail="${3:-}"
    if [[ "$result" == "ok" ]]; then
        log "OK: $name $detail"
    else
        log "FAIL: $name $detail"
        FAIL=1
    fi
}

log "Проверка конфигурации безопасности NetShield..."

# 1. IP forwarding
if command -v sysctl >/dev/null 2>&1; then
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    if [[ "$fwd" == "1" ]]; then
        check "IP forwarding" "ok"
    else
        check "IP forwarding" "fail" "(net.ipv4.ip_forward=$fwd)"
    fi
else
    check "sysctl" "skip" "(sysctl не найден)"
fi

# 2. nftables
if command -v nft >/dev/null 2>&1; then
    if nft list ruleset >/dev/null 2>&1; then
        rule_count=$(nft list ruleset 2>/dev/null | grep -c "rule" || true)
        check "nftables" "ok" ("$rule_count правил)")
    else
        check "nftables" "fail" "(ошибка чтения правил)"
    fi
else
    check "nftables" "skip" "(nft не найден)"
fi

# 3. SSH конфигурация
SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    root_login=$(grep -E '^[# ]*PermitRootLogin' "$SSH_CONFIG" | awk '{print $2}' || echo "yes")
    if [[ "$root_login" == "no" ]]; then
        check "SSH root login" "ok"
    else
        check "SSH root login" "warn" "(PermitRootLogin=$root_login)"
    fi
    max_auth=$(grep -E '^[# ]*MaxAuthTries' "$SSH_CONFIG" | awk '{print $2}' || echo "6")
    if [[ "$max_auth" =~ ^[0-9]+$ ]] && [[ "$max_auth" -le 5 ]]; then
        check "SSH max auth tries" "ok" ("$max_auth")
    else
        check "SSH max auth tries" "warn" ("$max_auth")
    fi
else
    check "SSH config" "skip" "($SSH_CONFIG не найден)"
fi

# 4. Открытые порты
if command -v ss >/dev/null 2>&1; then
    listening=$(ss -tuln 2>/dev/null | grep -c "LISTEN" || true)
    check "Listening ports" "ok" ("$listening портов")
else
    check "ss" "skip" "(ss не найден)"
fi

# 5. systemd служба NetShield
if systemctl list-unit-files netshield.service >/dev/null 2>&1; then
    ns_status=$(systemctl is-active netshield.service 2>/dev/null || echo "inactive")
    if [[ "$ns_status" == "active" ]]; then
        check "NetShield service" "ok"
    else
        check "NetShield service" "warn" ("статус: $ns_status")
    fi
else
    check "NetShield service" "skip" (юнит не установлен)
fi

# 6. База данных конфигурации
if [[ -f "netshield.db" ]] || [[ -f "${NETSHIELD_DB_PATH:-netshield.db}" ]]; then
    db_path="${NETSHIELD_DB_PATH:-netshield.db}"
    if sqlite3 "$db_path" "SELECT 1 FROM users LIMIT 1" >/dev/null 2>&1; then
        check "База данных" "ok" ("$db_path")
    else
        check "База данных" "warn" ("таблица users пуста или отсутствует")
    fi
else
    check "База данных" "warn" (файл netshield.db не найден)
fi

# 7. Python процесс
if pgrep -f "app.cli serve\|app.main:app" >/dev/null 2>&1; then
    check "Python process" "ok"
else
    check "Python process" "warn" (процесс не запущен)
fi

echo ""
if [[ "$FAIL" -eq 0 ]]; then
    log "Все критические проверки пройдены."
    exit 0
else
    log "Обнаружены проблемы. См. вывод выше."
    exit 1
fi
