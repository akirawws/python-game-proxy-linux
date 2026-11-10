from __future__ import annotations

import json

import pytest

ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "admin-pass-123"
CSRF_HEADER = "X-CSRF-Token"

LOGIN_URL = "/api/auth/login"
CSRF_URL = "/api/auth/csrf"
ME_URL = "/api/auth/me"
LOGOUT_URL = "/api/auth/logout"


def _csrf(client) -> str:
    response = client.get(CSRF_URL)
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _login(client, password: str = ADMIN_PASSWORD, login: str = ADMIN_LOGIN):
    token = _csrf(client)
    return client.post(
        LOGIN_URL,
        json={"login": login, "password": password},
        headers={CSRF_HEADER: token},
    )


class TestCsrf:
    def test_csrf_token_is_issued(self, client):
        token = _csrf(client)
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_csrf_token_is_stable_within_session(self, client):
        assert _csrf(client) == _csrf(client)

    def test_login_without_csrf_header_is_rejected(self, client):
        response = client.post(
            LOGIN_URL,
            json={"login": ADMIN_LOGIN, "password": ADMIN_PASSWORD},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"

    def test_login_with_wrong_csrf_header_is_rejected(self, client):
        _csrf(client)
        response = client.post(
            LOGIN_URL,
            json={"login": ADMIN_LOGIN, "password": ADMIN_PASSWORD},
            headers={CSRF_HEADER: "wrong-token"},
        )
        assert response.status_code == 403

    def test_unsafe_method_without_session_is_rejected(self, client):
        response = client.post(LOGIN_URL, json={"login": "x", "password": "y"})
        assert response.status_code == 403


class TestLogin:
    def test_login_success_returns_user_and_rotated_token(self, client):
        initial = _csrf(client)
        response = _login(client)

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["user"]["login"] == ADMIN_LOGIN
        assert payload["user"]["is_admin"] is True
        assert payload["csrf_token"] != initial

        me = client.get(ME_URL)
        assert me.status_code == 200
        assert me.json()["user"]["login"] == ADMIN_LOGIN

    def test_login_wrong_password_rejected(self, client):
        response = _login(client, password="totally-wrong-password")
        assert response.status_code == 401
        assert response.json()["detail"] == "Неверный логин или пароль"
        assert client.get(ME_URL).status_code == 401

    def test_login_unknown_user_rejected(self, client):
        response = _login(client, login="no-such-user")
        assert response.status_code == 401
        assert response.json()["detail"] == "Неверный логин или пароль"

    def test_login_validation(self, client):
        token = _csrf(client)
        response = client.post(
            LOGIN_URL,
            json={"login": "", "password": ""},
            headers={CSRF_HEADER: token},
        )
        assert response.status_code == 422

    def test_login_rejects_extra_fields(self, client):
        token = _csrf(client)
        response = client.post(
            LOGIN_URL,
            json={"login": ADMIN_LOGIN, "password": ADMIN_PASSWORD, "role": "admin"},
            headers={CSRF_HEADER: token},
        )
        assert response.status_code == 422


class TestAuthorization:
    def test_me_requires_auth(self, client):
        response = client.get(ME_URL)
        assert response.status_code == 401

    def test_api_requires_auth(self, client):
        for url in (
            "/api/servers",
            "/api/metrics/overview",
            "/api/events",
            "/api/rules",
            "/api/stats",
        ):
            assert client.get(url).status_code == 401, url

    def test_logout_clears_session(self, auth_client):
        token = _csrf(auth_client)
        response = auth_client.post(LOGOUT_URL, headers={CSRF_HEADER: token})
        assert response.status_code == 204
        assert auth_client.get(ME_URL).status_code == 401

    def test_logout_requires_csrf(self, auth_client):
        assert auth_client.post(LOGOUT_URL).status_code == 403

    def test_session_cookie_is_httponly(self, client):
        response = _login(client)
        cookie_header = response.headers.get("set-cookie", "")
        assert "httponly" in cookie_header.lower()
        assert "samesite=lax" in cookie_header.lower()


class TestRateLimit:
    def test_lockout_after_max_attempts(self, client):
        for _ in range(3):
            assert _login(client, password="wrong-password").status_code == 401

        blocked = _login(client, password="wrong-password")
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers

        still_blocked = _login(client)
        assert still_blocked.status_code == 429

    def test_success_resets_counter(self, client):
        assert _login(client, password="wrong-password").status_code == 401
        assert _login(client).status_code == 200
        assert client.get(ME_URL).status_code == 200


class TestAudit:
    def test_failed_login_is_audited_without_secrets(self, auth_client):
        _login(auth_client, password="secret-value-123")

        headers = {CSRF_HEADER: _csrf(auth_client)}
        response = auth_client.get("/api/audit", params={"hours": 1}, headers=headers)
        assert response.status_code == 200

        items = response.json()["items"]
        events = [item for item in items if item["action"] == "auth.login"]
        assert events, items

        failures = [item for item in events if item["result"] == "fail"]
        assert failures

        raw = json.dumps(items, ensure_ascii=False)
        assert "secret-value-123" not in raw
        assert ADMIN_PASSWORD not in raw

    def test_successful_login_is_audited(self, auth_client):
        headers = {CSRF_HEADER: _csrf(auth_client)}
        response = auth_client.get(
            "/api/audit", params={"action": "auth.login"}, headers=headers
        )
        assert response.status_code == 200
        assert any(item["result"] == "ok" for item in response.json()["items"])

    def test_logout_is_audited(self, client):
        assert _login(client).status_code == 200
        token = _csrf(client)
        client.post(LOGOUT_URL, headers={CSRF_HEADER: token})
        assert _login(client).status_code == 200

        token = _csrf(client)
        response = client.get(
            "/api/audit", params={"action": "auth.logout"}, headers={CSRF_HEADER: token}
        )
        assert response.status_code == 200
        assert response.json()["total"] >= 1
