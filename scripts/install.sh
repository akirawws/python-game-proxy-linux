#!/usr/bin/env bash
# install.sh — установка зависимостей и настройка шлюза NetShield
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

log() { printf '[netshield-install] %s\n' "$*"; }
warn() { printf '[netshield-install] ВНИМАНИЕ: %s\n' "$*" >&2; }
die() { printf '[netshield-install] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root: sudo bash scripts/install.sh"
[[ "$(uname -s)" == "Linux" ]] || die "скрипт предназначен для Linux"

# Проверка необходимых инструментов
for cmd in apt-get python3 pip3 nft sysctl iptables; do
    command -v "$cmd" >/dev/null 2>&1 || die "не найден $cmd (установите необходимые пакеты)"
done

log "Обновление списка пакетов..."
apt-get update -y

log "Установка пакетов системы..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nftables \
    conntrack \
    iptables \
    procps \
    iproute2 \
    openssh-server \
    sudo \
    curl \
    tar

log "Создание пользователя netshield..."
id -u netshield >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin netshield

log "Настройка виртуального окружения Python..."
VENV_DIR="$REPO_ROOT/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements.txt"

log "Копирование файла окружения..."
if [[ ! -f "$REPO_ROOT/.env" ]]; then
    cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
    warn "Файл .env создан из примера. Отредактируйте его перед запуском (SECRET_KEY, CLICKHOUSE_*)."
fi

log "Установка完成. Для применения сетевых настроек выполните: sudo bash scripts/configure_network.sh"
log "Для создания базовых правил брандмауэра: sudo bash scripts/configure_firewall.sh"
log "Для запуска службы: sudo bash scripts/configure_service.sh && sudo systemctl start netshield.service"
