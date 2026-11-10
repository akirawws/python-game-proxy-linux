#!/usr/bin/env bash
# backup_config.sh — резервное копирование конфигурации и правил
set -euo pipefail

BACKUP_FILE="${1:-netshield_backup_$(date +%Y%m%d_%H%M%S).tar.gz}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

log() { printf '[netshield-backup] %s\n' "$*"; }
die() { printf '[netshield-backup] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запустите с правами root"

log "Создание резервной копии: $BACKUP_FILE"

# Собираем список файлов для бэкапа
FILES_TO_BACKUP=()

# Конфигурация приложения
[[ -f "$REPO_ROOT/.env" ]] && FILES_TO_BACKUP+=("$REPO_ROOT/.env")
[[ -f "$REPO_ROOT/netshield.db" ]] && FILES_TO_BACKUP+=("$REPO_ROOT/netshield.db")

# Скрипты настройки
[[ -d "$REPO_ROOT/scripts" ]] && FILES_TO_BACKUP+=("$REPO_ROOT/scripts")

# Служба systemd
[[ -f "/etc/systemd/system/netshield.service" ]] && FILES_TO_BACKUP+=("/etc/systemd/system/netshield.service")

# Правила nftables
[[ -f "/etc/nftables.conf" ]] && FILES_TO_BACKUP+=("/etc/nftables.conf")

# SSH конфигурация
[[ -f "/etc/ssh/sshd_config" ]] && FILES_TO_BACKUP+=("/etc/ssh/sshd_config")

if [[ ${#FILES_TO_BACKUP[@]} -eq 0 ]]; then
    die "нечего бэкапить: нет файлов конфигурации"
fi

tar -czf "$BACKUP_FILE" "${FILES_TO_BACKUP[@]}"

log "Резервная копия создана: $BACKUP_FILE"
log "Включённые файлы:"
for f in "${FILES_TO_BACKUP[@]}"; do
    echo "  - $f"
done
