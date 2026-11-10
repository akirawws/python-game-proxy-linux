#!/usr/bin/env bash
# secure_ssh.sh — укрепление SSH-доступа
set -euo pipefail

SSH_CONFIG="/etc/ssh/sshd_config"
CHECK=0

while (( $# > 0 )); do
    case "$1" in
        --check) CHECK=1; shift ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

log() { printf '[netshield-ssh] %s\n' "$*"; }
die() { printf '[netshield-ssh] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root"
[[ -f "$SSH_CONFIG" ]] || die "файл $SSH_CONFIG не найден (установите openssh-server)"

log "Создание резервной копии конфигурации SSH..."
cp -a "$SSH_CONFIG" "${SSH_CONFIG}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

# Применяем безопасные настройки (добавляем или заменяем существующие)
set_ssh_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^[# ]*${key}[ ]+" "$SSH_CONFIG"; then
        sed -i "s/^[# ]*${key}[ ].*/${key} ${value}/" "$SSH_CONFIG"
    else
        echo "${key} ${value}" >> "$SSH_CONFIG"
    fi
}

log "Настройка параметров безопасности SSH..."
set_ssh_option "PermitRootLogin" "no"
set_ssh_option "PasswordAuthentication" "yes"
set_ssh_option "PubkeyAuthentication" "yes"
set_ssh_option "MaxAuthTries" "3"
set_ssh_option "LoginGraceTime" "60"
set_ssh_option "ClientAliveInterval" "300"
set_ssh_option "ClientAliveCountMax" "3"
set_ssh_option "X11Forwarding" "no"
set_ssh_option "AllowTcpForwarding" "no"
set_ssh_option "Protocol" "2"

# Ограничиваем доступ только для пользователя netshield, если существует
if id netshield >/dev/null 2>&1; then
    if ! grep -qE "^AllowUsers" "$SSH_CONFIG"; then
        echo "AllowUsers netshield" >> "$SSH_CONFIG"
    fi
fi

log "Проверка синтаксиса конфигурации..."
if command -v sshd >/dev/null 2>&1; then
    sshd -t 2>&1 || die "ошибка синтаксиса в $SSH_CONFIG"
fi

if (( CHECK )); then
    echo "=== Текущие настройки SSH ==="
    grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|LoginGraceTime|ClientAliveInterval|ClientAliveCountMax|X11Forwarding|AllowTcpForwarding|Protocol|AllowUsers)' "$SSH_CONFIG" || true
fi

log "Перезапустите SSH для применения: systemctl restart sshd"
log "Готово."
