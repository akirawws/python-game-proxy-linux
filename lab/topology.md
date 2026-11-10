# Логическая топология стенда тестирования NetShield

Стенд представляет собой изолированную сеть на базе Linux network namespaces, через которую проходит трафик от клиента к защищаемым серверам через шлюз NetShield.

## Компоненты стенда

```
ns-client (клиент) --- veth-cl/veth-gw-cl --- ns-gw (шлюз NetShield) --- veth-gw-be/veth-be --- ns-backend (защищаемый сервер)
```

| Namespace | Роль | Интерфейс | IP-адрес | Маршрут по умолчанию |
|-----------|------|-----------|----------|----------------------|
| ns-client | Тестовый клиент | veth-cl | 10.10.0.2/24 | via 10.10.0.1 |
| ns-gw | Шлюз NetShield (IP forwarding, nftables, NAT) | veth-gw-cl / veth-gw-be | 10.10.0.1/24, 10.20.0.1/24 | — |
| ns-backend | Защищаемый сервер (Web + UDP) | veth-be | 10.20.0.2/24 | via 10.20.0.1 |

## Сети

- **LAN (клиент — шлюз):** 10.10.0.0/24
- **WAN (шлюз — backend):** 10.20.0.0/24

## Сервисы на backend

- HTTP (TCP 8080) — веб-сервис
- Game (UDP 9090) — игровой сервис

## Инструменты тестирования

- `iperf3` — генерация нагрузки
- `wrk` / `k6` — нагрузочное тестирование веб-сервиса
- `tcpdump`, `Wireshark` — анализ сетевого трафика
- `nftables`, `conntrack` — управление фильтрацией и состоянием соединений
- `pytest` — автоматические тесты

## Запуск стенда

```bash
sudo bash lab/setup_lab.sh [--force] [--no-verify] [--http-port 8080] [--udp-port 9090]
```

Очистка:
```bash
sudo bash lab/teardown_lab.sh
```

## Требования

- Linux (запуск только на Linux из-за network namespaces)
- Права root
- iproute2, nftables, procps, python3
