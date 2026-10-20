# netshield

Система обнаружения аномального сетевого трафика и защиты Web- и игровых серверов на базе Python и Linux.

## Архитектура

- `app/collector` — сбор метрик (интерфейсы, nftables, conntrack)
- `app/detector` — алгоритмы обнаружения без нейросетей (A, B, C, D)
- `app/firewall` — Rule Manager и применение правил nftables
- `app/api` — Web API (auth, servers, metrics, events, rules)
- `app/security` — сессии, аудит, валидация
- `app/storage` — модели и репозиторий (ClickHouse + SQLite)
- `scripts/` — установка и настройка безопасности Linux
- `web/` — шаблоны и статика веб-панели
