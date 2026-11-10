from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import reset_settings_cache
from app.storage.factory import reset_storage

ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "admin-pass-123"
CSRF_HEADER = "X-CSRF-Token"


@pytest.fixture()
def application(tmp_path, monkeypatch):
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "netshield-test.db"))
    monkeypatch.setenv("NETSHIELD_SECRET_KEY", "test-secret-key-not-for-prod")
    monkeypatch.setenv("NETSHIELD_ADMIN_LOGIN", ADMIN_LOGIN)
    monkeypatch.setenv("NETSHIELD_ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("CSRF_ENABLED", "true")
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("LOGIN_LOCKOUT_SECONDS", "900")

    reset_settings_cache()
    reset_storage()

    from app.main import create_app

    app = create_app()
    yield app

    reset_storage()
    reset_settings_cache()


@pytest.fixture()
def client(application):
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture()
def csrf(client) -> str:
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.fixture()
def auth_client(client, csrf):
    response = client.post(
        "/api/auth/login",
        json={"login": ADMIN_LOGIN, "password": ADMIN_PASSWORD},
        headers={CSRF_HEADER: csrf},
    )
    assert response.status_code == 200, response.text
    return client


@pytest.fixture()
def auth_headers(client, auth_client) -> dict:
    token = client.get("/api/auth/csrf").json()["csrf_token"]
    return {CSRF_HEADER: token}
