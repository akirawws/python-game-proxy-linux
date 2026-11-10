#!/usr/bin/env bash
# restore_config.sh — восстановление конфигурации из резервной копии
set -e

BACKUP_FILE="${1:-netshield_backup.tar.gz}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Файл резервной копии не найден: $BACKUP_FILE"
    exit 1
fi

echo "Восстановление из $BACKUP_FILE..."
tar -xzf "$BACKUP_FILE" -C /
echo "Готово. Перезапустите службу: systemctl restart netshield.service"
