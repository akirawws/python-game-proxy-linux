from __future__ import annotations

import json
from datetime import timedelta

import pytest

from app.storage.factory import get_config_storage
from app.storage.repository import utcnow

ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "admin-pass-123"
CSRF_HEADER = "X-CSRF-Token"


def _csrf(client) -> str:
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.fixture()
def headers(auth_client) -> dict:
    return {CSRF_HEADER: _csrf(auth_client)}


def _server_payload(**overrides) -> dict:
    payload = {
        "name": "Game #1",
        "ip": "203.0.113.10",
        "interface": "eth0",
        "service_type": "game",
        "internal_ip": "10.0.0.10",
        "internal_port": 27015,
        "profile": "game",
        "description": "тестовый игровой сервер",
        "is_active": True,
        "max_pps": 5000,
        "max_bps": 100_000_000,
        "max_new_tcp_per_s": 200,
        "max_udp_pps": 3000,
        "max_new_sources": 100,
        "max_connections": 2000,
        "ports": [
            {"port": 27015, "protocol": "udp", "service_type": "game"},
            {"port": 8080, "protocol": "tcp", "service_type": "web"},
        ],
    }
    payload.update(overrides)
    return payload


def _create_server(client, headers, **overrides) -> dict:
    response = client.post("/api/servers", json=_server_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _insert_metric(server_id: int, offset_seconds: int = 0) -> None:
    repository = get_config_storage()
    ts = (utcnow() - timedelta(seconds=offset_seconds)).isoformat()
    repository.insert_row(
        "traffic_metrics",
        {
            "server_id": server_id,
            "timestamp": ts,
            "in_bytes": 1000,
            "out_bytes": 2000,
            "in_pps": 12.5,
            "out_pps": 7.5,
            "in_bps": 1500.0,
            "out_bps": 900.0,
        },
    )
    repository.insert_row(
        "connection_metrics",
        {
            "server_id": server_id,
            "timestamp": ts,
            "tcp_new": 5,
            "udp_pps": 3.5,
            "conntrack_count": 42,
            "new_sources": 2,
        },
    )


def _insert_event(server_id: int, **overrides) -> None:
    repository = get_config_storage()
    payload = {
        "server_id": server_id,
        "timestamp": utcnow().isoformat(),
        "event_type": "udp_flood",
        "score": 0.91,
        "severity": "high",
        "details": '{"pps": 120000}',
        "action_status": "proposed",
        "protocol": "udp",
    }
    payload.update(overrides)
    repository.insert_row("anomaly_events", payload)


class TestServerCrud:
    def test_create_and_list(self, auth_client, headers):
        created = _create_server(auth_client, headers)

        assert created["name"] == "Game #1"
        assert created["ip"] == "203.0.113.10"
        assert created["profile"] == "game"
        assert len(created["ports"]) == 2
        assert {p["port"] for p in created["ports"]} == {27015, 8080}

        listing = auth_client.get("/api/servers")
        assert listing.status_code == 200
        assert listing.json()["total"] == 1

    def test_get_single_and_404(self, auth_client, headers):
        created = _create_server(auth_client, headers)

        found = auth_client.get(f"/api/servers/{created['id']}")
        assert found.status_code == 200
        assert found.json()["id"] == created["id"]

        missing = auth_client.get("/api/servers/9999")
        assert missing.status_code == 404

    def test_update_server(self, auth_client, headers):
        created = _create_server(auth_client, headers)

        response = auth_client.patch(
            f"/api/servers/{created['id']}",
            json={"description": "обновлено", "max_pps": 9000},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["description"] == "обновлено"
        assert response.json()["max_pps"] == 9000

    def test_replace_ports(self, auth_client, headers):
        created = _create_server(auth_client, headers)

        response = auth_client.put(
            f"/api/servers/{created['id']}/ports",
            json=[{"port": 443, "protocol": "tcp", "service_type": "web"}],
            headers=headers,
        )
        assert response.status_code == 200
        ports = response.json()["ports"]
        assert len(ports) == 1
        assert ports[0]["port"] == 443

    def test_delete_server(self, auth_client, headers):
        created = _create_server(auth_client, headers)

        response = auth_client.delete(f"/api/servers/{created['id']}", headers=headers)
        assert response.status_code == 204
        assert auth_client.get(f"/api/servers/{created['id']}").status_code == 404

    def test_mutation_requires_csrf(self, auth_client):
        response = auth_client.post("/api/servers", json=_server_payload())
        assert response.status_code == 403


class TestValidation:
    def test_invalid_ip_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers", json=_server_payload(ip="999.1.1.1"), headers=headers
        )
        assert response.status_code == 422

    def test_private_ip_accepted(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers", json=_server_payload(ip="192.168.1.5"), headers=headers
        )
        assert response.status_code == 201

    def test_ipv6_accepted(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers", json=_server_payload(ip="2001:db8::1"), headers=headers
        )
        assert response.status_code == 201

    def test_port_out_of_range_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers",
            json=_server_payload(ports=[{"port": 70000, "protocol": "tcp"}]),
            headers=headers,
        )
        assert response.status_code == 422

    def test_unknown_protocol_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers",
            json=_server_payload(ports=[{"port": 80, "protocol": "sctp"}]),
            headers=headers,
        )
        assert response.status_code == 422

    def test_duplicate_ports_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers",
            json=_server_payload(
                ports=[
                    {"port": 80, "protocol": "tcp"},
                    {"port": 80, "protocol": "tcp"},
                ]
            ),
            headers=headers,
        )
        assert response.status_code == 422

    def test_shell_command_field_rejected(self, auth_client, headers):
        payload = _server_payload()
        payload["command"] = "rm -rf /"
        response = auth_client.post("/api/servers", json=payload, headers=headers)
        assert response.status_code == 422

    def test_shell_injection_in_name_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers",
            json=_server_payload(name="bad\nname"),
            headers=headers,
        )
        assert response.status_code == 422

    def test_bad_interface_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/servers",
            json=_server_payload(interface="eth0; reboot"),
            headers=headers,
        )
        assert response.status_code == 422

    def test_patch_shell_injection_rejected(self, auth_client, headers):
        created = _create_server(auth_client, headers)
        response = auth_client.patch(
            f"/api/servers/{created['id']}", json={"name": "bad\nname"}, headers=headers
        )
        assert response.status_code == 422

    def test_patch_empty_ip_rejected(self, auth_client, headers):
        created = _create_server(auth_client, headers)
        response = auth_client.patch(
            f"/api/servers/{created['id']}", json={"ip": ""}, headers=headers
        )
        assert response.status_code == 422


class TestServerIsolation:
    def test_rule_for_foreign_port_rejected(self, auth_client, headers):
        first = _create_server(auth_client, headers, name="A", ip="203.0.113.1")
        second = _create_server(
            auth_client,
            headers,
            name="B",
            ip="203.0.113.2",
            ports=[{"port": 9090, "protocol": "tcp", "service_type": "web"}],
        )

        response = auth_client.post(
            "/api/rules",
            json={
                "server_id": second["id"],
                "action": "block_port",
                "port": 27015,
                "protocol": "udp",
            },
            headers=headers,
        )
        assert response.status_code == 400
        assert "Порт не принадлежит" in response.json()["detail"]

        ok = auth_client.post(
            "/api/rules",
            json={
                "server_id": second["id"],
                "action": "block_port",
                "port": 9090,
                "protocol": "tcp",
            },
            headers=headers,
        )
        assert ok.status_code == 201

    def test_rule_for_missing_server_rejected(self, auth_client, headers):
        response = auth_client.post(
            "/api/rules",
            json={"server_id": 4321, "action": "rate_limit", "ip": "1.2.3.4"},
            headers=headers,
        )
        assert response.status_code == 400


class TestMetrics:
    def test_traffic_without_data(self, auth_client):
        response = auth_client.get("/api/metrics/traffic", params={"range": "5m"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["has_data"] is False
        assert payload["points"] == []
        assert payload["message"]

    def test_traffic_with_data(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_metric(server["id"], offset_seconds=5)

        response = auth_client.get(
            "/api/metrics/traffic", params={"range": "5m", "server_id": server["id"]}
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["has_data"] is True
        assert payload["stale"] is False
        assert payload["points"]
        point = payload["points"][-1]
        assert point["in_pps"] == pytest.approx(12.5, abs=0.01)
        assert "ts" in point and "bucket" not in point

    def test_connections_with_data(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_metric(server["id"])

        response = auth_client.get(
            "/api/metrics/connections",
            params={"range": "5m", "server_id": server["id"]},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["has_data"] is True
        assert payload["points"][-1]["conntrack_count"] == pytest.approx(42, abs=0.01)

    def test_invalid_range_rejected(self, auth_client):
        assert auth_client.get("/api/metrics/traffic", params={"range": "42y"}).status_code == 422

    def test_overview(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_metric(server["id"], offset_seconds=2)

        response = auth_client.get("/api/metrics/overview")
        assert response.status_code == 200
        payload = response.json()
        assert payload["gateway"]["servers_total"] == 1
        assert payload["gateway"]["detection_mode"] == "observation"
        assert payload["items"][0]["has_data"] is True
        assert payload["items"][0]["conntrack_count"] == 42


class TestStatistics:
    def test_empty_dataset(self, auth_client):
        response = auth_client.get("/api/stats", params={"range": "5m"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["has_data"] is False
        assert payload["message"]
        assert payload["traffic"]["series"] == []
        assert payload["events"]["total"] == 0
        assert payload["rules"]["active"] == 0
        assert payload["range"] == "5m"

    def test_populated_dataset(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_metric(server["id"], offset_seconds=5)
        _insert_event(server["id"], severity="high", protocol="udp")
        _insert_event(
            server["id"],
            severity="low",
            protocol="tcp",
            event_type="syn_flood",
            action_status="applied",
        )
        rule = auth_client.post(
            "/api/rules",
            json={"server_id": server["id"], "action": "alert", "ip": "198.51.100.11"},
            headers=headers,
        )
        assert rule.status_code == 201

        response = auth_client.get(
            "/api/stats", params={"range": "5m", "server_id": server["id"]}
        )
        assert response.status_code == 200
        payload = response.json()

        assert payload["has_data"] is True
        assert payload["server_id"] == server["id"]
        assert payload["traffic"]["has_data"] is True
        assert payload["traffic"]["peak_in_pps"] == pytest.approx(12.5, abs=0.01)
        assert payload["traffic"]["series"][-1]["in_pps"] == pytest.approx(12.5, abs=0.01)

        assert payload["events"]["total"] == 2
        by_severity = {row["severity"]: row["count"] for row in payload["events"]["by_severity"]}
        assert by_severity == {"high": 1, "low": 1}
        by_protocol = {
            row["protocol"]: row["count"] for row in payload["events"]["by_protocol"]
        }
        assert by_protocol == {"udp": 1, "tcp": 1}
        by_type = {
            row["event_type"]: row["count"] for row in payload["events"]["by_type"]
        }
        assert by_type == {"udp_flood": 1, "syn_flood": 1}
        by_status = {
            row["action_status"]: row["count"] for row in payload["events"]["by_status"]
        }
        assert by_status == {"proposed": 1, "applied": 1}

        assert payload["rules"]["active"] == 1
        assert payload["rules"]["temporary"] == 1
        assert payload["rules"]["permanent"] == 0
        assert payload["rules"]["expired"] == 0
        assert payload["rules"]["created_in_period"] == 1
        assert payload["rules"]["by_action"] == [{"action": "alert", "count": 1}]

    def test_invalid_range_rejected(self, auth_client):
        assert auth_client.get("/api/stats", params={"range": "42y"}).status_code == 422


class TestEvents:
    def test_empty_events(self, auth_client):
        response = auth_client.get("/api/events")
        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 0
        assert payload["has_data"] is False
        assert payload["message"]

    def test_filters(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_event(server["id"], severity="high", protocol="udp")
        _insert_event(
            server["id"],
            severity="low",
            protocol="tcp",
            event_type="syn_flood",
            action_status="applied",
        )

        all_events = auth_client.get("/api/events").json()
        assert all_events["total"] == 2

        high = auth_client.get("/api/events", params={"severity": "high"}).json()
        assert high["total"] == 1
        assert high["items"][0]["severity"] == "high"
        assert high["items"][0]["server_name"] == "Game #1"

        by_proto = auth_client.get("/api/events", params={"protocol": "tcp"}).json()
        assert by_proto["total"] == 1
        assert by_proto["items"][0]["event_type"] == "syn_flood"

        by_status = auth_client.get(
            "/api/events", params={"action_status": "applied"}
        ).json()
        assert by_status["total"] == 1

        by_server = auth_client.get(
            "/api/events", params={"server_id": server["id"]}
        ).json()
        assert by_server["total"] == 2

    def test_stats(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_event(server["id"], severity="high")
        _insert_event(server["id"], severity="high")
        _insert_event(server["id"], severity="low", protocol="tcp")

        response = auth_client.get("/api/events/stats")
        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 3
        assert payload["group_by"] == "severity"
        by_severity = {row["severity"]: row["count"] for row in payload["items"]}
        assert by_severity == {"high": 2, "low": 1}

    def test_stats_group_by_protocol(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        _insert_event(server["id"], protocol="udp")
        _insert_event(server["id"], protocol="tcp", event_type="syn_flood")

        response = auth_client.get("/api/events/stats", params={"group_by": "protocol"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["group_by"] == "protocol"
        by_protocol = {row["protocol"]: row["count"] for row in payload["items"]}
        assert by_protocol == {"udp": 1, "tcp": 1}

    def test_stats_invalid_group_by_rejected(self, auth_client):
        response = auth_client.get("/api/events/stats", params={"group_by": "source_ip"})
        assert response.status_code == 422

    def test_invalid_severity_rejected(self, auth_client):
        assert auth_client.get("/api/events", params={"severity": "catastrophic"}).status_code == 422


class TestRules:
    def test_apply_rule_is_pending_without_firewall(self, auth_client, headers):
        server = _create_server(auth_client, headers)

        response = auth_client.post(
            "/api/rules",
            json={
                "server_id": server["id"],
                "action": "rate_limit",
                "ip": "198.51.100.7",
                "port": 27015,
                "protocol": "udp",
                "ttl_seconds": 120,
                "reason": "udp flood",
            },
            headers=headers,
        )
        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["status"] == "pending"
        assert payload["rule_id"]

        listing = auth_client.get("/api/rules").json()
        assert listing["total"] == 1
        rule = listing["items"][0]
        assert rule["ip"] == "198.51.100.7"
        assert rule["action"] == "rate_limit"
        assert rule["reason"] == "udp flood"
        assert rule["rule_type"] == "temporary"

    def test_rule_without_ttl_is_permanent(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        response = auth_client.post(
            "/api/rules",
            json={
                "server_id": server["id"],
                "action": "block_source",
                "ip": "198.51.100.8",
                "ttl_seconds": 0,
            },
            headers=headers,
        )
        assert response.status_code == 201
        rule = auth_client.get("/api/rules").json()["items"][0]
        assert rule["rule_type"] == "permanent"

    def test_cancel_rule(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        created = auth_client.post(
            "/api/rules",
            json={"server_id": server["id"], "action": "alert", "ip": "198.51.100.9"},
            headers=headers,
        ).json()

        response = auth_client.delete(f"/api/rules/{created['rule_id']}", headers=headers)
        assert response.status_code == 200
        assert response.json()["status"] == "cancelled"
        assert auth_client.get("/api/rules").json()["total"] == 0

    def test_cancel_missing_rule(self, auth_client, headers):
        assert auth_client.delete("/api/rules/9999", headers=headers).status_code == 404

    def test_invalid_action_rejected(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        response = auth_client.post(
            "/api/rules",
            json={"server_id": server["id"], "action": "format_disk"},
            headers=headers,
        )
        assert response.status_code == 422

    def test_rule_audited(self, auth_client, headers):
        server = _create_server(auth_client, headers)
        auth_client.post(
            "/api/rules",
            json={"server_id": server["id"], "action": "alert", "ip": "198.51.100.10"},
            headers=headers,
        )
        audit = auth_client.get("/api/audit", params={"action": "rule.apply"}).json()
        assert audit["total"] >= 1


class TestSettings:
    def test_defaults(self, auth_client):
        response = auth_client.get("/api/settings")
        assert response.status_code == 200
        payload = response.json()
        assert payload["detection_mode"] == "observation"
        assert payload["auto_actions_enabled"] is False

    def test_update_and_audit(self, auth_client, headers):
        response = auth_client.put(
            "/api/settings",
            json={
                "detection_mode": "auto",
                "auto_actions_enabled": True,
                "collection_interval_sec": 2,
                "confirmation_intervals": 4,
                "cooldown_seconds": 90,
                "max_concurrent_blocks": 10,
                "metrics_retention_days": 14,
                "event_retention_days": 30,
            },
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["detection_mode"] == "auto"
        assert payload["collection_interval_sec"] == 2

        audit = auth_client.get("/api/audit", params={"action": "settings.update"}).json()
        assert audit["total"] >= 1

        overview = auth_client.get("/api/metrics/overview").json()
        assert overview["gateway"]["detection_mode"] == "auto"
        assert overview["gateway"]["auto_actions_enabled"] is True

    def test_auto_mode_forces_auto_actions(self, auth_client, headers):
        response = auth_client.put(
            "/api/settings",
            json={"detection_mode": "auto", "auto_actions_enabled": False},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["auto_actions_enabled"] is True

    def test_invalid_mode_rejected(self, auth_client, headers):
        response = auth_client.put(
            "/api/settings", json={"detection_mode": "yolo"}, headers=headers
        )
        assert response.status_code == 422


class TestSecurityAndHealth:
    def test_security_status(self, auth_client):
        response = auth_client.get("/api/security/status")
        assert response.status_code == 200
        payload = response.json()
        names = {check["name"] for check in payload["checks"]}
        assert "CSRF-защита" in names
        assert "Защищаемые серверы" in names
        for check in payload["checks"]:
            assert check["status"] in ("ok", "warn", "error")
            assert "password" not in json.dumps(check).lower()

    def test_health_is_public(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["config_db"] is True

    def test_openapi_lists_endpoints(self, client):
        response = client.get("/api/openapi.json")
        assert response.status_code == 200
        paths = response.json()["paths"]
        for path in ("/api/stats", "/api/auth/login", "/api/servers", "/api/rules"):
            assert path in paths

    def test_spa_served_or_build_hint(self, client):
        response = client.get("/")
        if response.status_code == 200:
            assert "text/html" in response.headers["content-type"]
        else:
            assert response.status_code == 503
            assert "npm run build" in response.json()["detail"]

    def test_security_headers_present(self, client):
        response = client.get("/api/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Request-ID"]
