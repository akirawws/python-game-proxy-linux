#!/usr/bin/env bash
# configure_service.sh — создание службы systemd для Python-приложения
set -e

SERVICE_FILE="/etc/systemd/system/netshield.service"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Создание службы systemd: $SERVICE_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=NetShield — защита от аномального трафика
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python -m app.cli serve
Restart=on-failure
User=netshield
Environment=NETSHIELD_HOST=0.0.0.0
Environment=NETSHIELD_PORT=8000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netshield.service

echo "Готово. Запуск: systemctl start netshield.service"
