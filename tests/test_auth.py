"""Authentication tests: fail-closed startup, login-required enforcement, the
local (argon2) login round-trip, and OIDC callback handling against a mocked
provider.

Each test loads a fresh copy of ``app/app.py`` with a throwaway database and a
specific auth configuration, using ``monkeypatch`` so environment changes are
undone afterwards (and don't leak into the engine/security suites).
"""
import importlib.util
import os
import uuid

import pytest

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "app.py")

# Every auth-relevant env var is cleared before each load so tests are hermetic.
_AUTH_ENV_KEYS = [
    "CRL_ALLOW_OPEN_MODE", "CRL_BOOTSTRAP_ADMIN_USERNAME", "CRL_BOOTSTRAP_ADMIN_PASSWORD",
    "CRL_SESSION_SECRET", "CRL_SESSION_COOKIE_SECURE", "CRL_LOCAL_LOGIN_ENABLED",
    "CRL_OIDC_ISSUER", "CRL_OIDC_CLIENT_ID", "CRL_OIDC_CLIENT_SECRET", "CRL_OIDC_SCOPES",
    "CRL_OIDC_GROUP_CLAIM", "CRL_OIDC_ALLOWED_GROUPS", "CRL_PUBLIC_BASE_URL",
]

_HDR = {"X-Requested-With": "XMLHttpRequest"}   # satisfies the CSRF guard


def load_app(tmp_path, monkeypatch, env):
    for k in _AUTH_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "0")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location("app_auth_" + uuid.uuid4().hex, APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Fail-closed startup
# --------------------------------------------------------------------------- #
def test_refuses_to_start_with_no_auth_and_no_optin(tmp_path, monkeypatch):
    """No auth configured and no explicit open-mode opt-in => refuse to start."""
    with pytest.raises(RuntimeError, match="Refusing to start"):
        load_app(tmp_path, monkeypatch, {})


def test_open_mode_optin_allows_anonymous_access(tmp_path, monkeypatch):
    mod = load_app(tmp_path, monkeypatch, {"CRL_ALLOW_OPEN_MODE": "true"})
    assert mod.auth_active() is False
    c = mod.app.test_client()
    assert c.get("/api/monitors").status_code == 200
    me = c.get("/api/auth/me")
    assert me.status_code == 200 and me.get_json()["subject"] == "__anonymous__"


# --------------------------------------------------------------------------- #
# Login-required enforcement (local/bootstrap admin)
# --------------------------------------------------------------------------- #
@pytest.fixture
def admin_app(tmp_path, monkeypatch):
    return load_app(tmp_path, monkeypatch, {
        "CRL_BOOTSTRAP_ADMIN_PASSWORD": "s3cret-pw",
        "CRL_SESSION_SECRET": "x" * 40,
        "CRL_SESSION_COOKIE_SECURE": "false",
    })


def test_login_required_enforced(admin_app):
    assert admin_app.auth_active() is True
    c = admin_app.app.test_client()
    # API requires a session...
    assert c.get("/api/monitors").status_code == 401
    assert c.post("/api/monitors", json={}, headers=_HDR).status_code == 401
    # ...but the health check stays public (used by the container HEALTHCHECK).
    assert c.get("/api/status").status_code == 200


def test_local_login_roundtrip(admin_app):
    c = admin_app.app.test_client()
    # wrong password
    r = c.post("/api/auth/login", json={"username": "admin", "password": "nope"}, headers=_HDR)
    assert r.status_code == 401
    # correct password -> session established
    r = c.post("/api/auth/login", json={"username": "admin", "password": "s3cret-pw"}, headers=_HDR)
    assert r.status_code == 200 and r.get_json()["subject"] == "admin"
    assert c.get("/api/monitors").status_code == 200
    assert c.get("/api/auth/me").get_json()["provider"] == "local"
    # logout clears the session
    assert c.post("/api/auth/logout", headers=_HDR).status_code == 204
    assert c.get("/api/monitors").status_code == 401


def test_password_is_hashed_with_argon2(admin_app):
    with __import__("contextlib").closing(admin_app.raw_db()) as db:
        row = db.execute("SELECT password_hash FROM users WHERE subject='admin'").fetchone()
    assert row["password_hash"].startswith("$argon2")


def test_local_login_disabled(tmp_path, monkeypatch):
    mod = load_app(tmp_path, monkeypatch, {
        "CRL_BOOTSTRAP_ADMIN_PASSWORD": "pw", "CRL_SESSION_SECRET": "k" * 40,
        "CRL_LOCAL_LOGIN_ENABLED": "false", "CRL_SESSION_COOKIE_SECURE": "false",
    })
    c = mod.app.test_client()
    r = c.post("/api/auth/login", json={"username": "admin", "password": "pw"}, headers=_HDR)
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# OIDC callback handling (mocked provider)
# --------------------------------------------------------------------------- #
class _FakeOIDCClient:
    """Stand-in for the authlib client: records the redirect URI and returns a
    canned token with userinfo claims (no network, no real state exchange)."""
    claims = {"sub": "ak-sub-123", "email": "alice@example.com", "name": "Alice",
              "groups": ["crl-users"]}
    last_redirect_uri = None

    def authorize_redirect(self, redirect_uri):
        from flask import redirect
        _FakeOIDCClient.last_redirect_uri = redirect_uri
        return redirect("https://idp.example.com/authorize?state=s&nonce=n")

    def authorize_access_token(self):
        return {"userinfo": dict(_FakeOIDCClient.claims)}


@pytest.fixture
def oidc_app(tmp_path, monkeypatch):
    mod = load_app(tmp_path, monkeypatch, {
        "CRL_OIDC_ISSUER": "https://idp.example.com/application/o/crl/",
        "CRL_OIDC_CLIENT_ID": "cid", "CRL_OIDC_CLIENT_SECRET": "csecret",
        "CRL_SESSION_SECRET": "z" * 40, "CRL_SESSION_COOKIE_SECURE": "false",
    })
    monkeypatch.setattr(mod, "_oidc_client", lambda: _FakeOIDCClient())
    return mod


def test_oidc_enabled_and_config(oidc_app):
    assert oidc_app.OIDC_ENABLED is True and oidc_app.auth_active() is True
    cfg = oidc_app.app.test_client().get("/api/auth/config").get_json()
    assert cfg["oidc_enabled"] is True
    assert cfg["oidc_login_url"] == "/api/auth/oidc/login"


def test_oidc_login_redirects_to_idp(oidc_app):
    c = oidc_app.app.test_client()
    r = c.get("/api/auth/oidc/login")
    assert r.status_code == 302
    assert r.headers["Location"].startswith("https://idp.example.com/authorize")
    # The callback URL is derived from the request when no public base URL is set.
    assert _FakeOIDCClient.last_redirect_uri.endswith("/api/auth/oidc/callback")


def test_oidc_callback_provisions_by_sub(oidc_app):
    c = oidc_app.app.test_client()
    r = c.get("/api/auth/oidc/callback?state=s&code=c")
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    me = c.get("/api/auth/me").get_json()
    assert me["provider"] == "oidc" and me["subject"] == "ak-sub-123"
    assert c.get("/api/monitors").status_code == 200
    # Identity is the sub; the row is keyed on it, with email as a display field.
    with __import__("contextlib").closing(oidc_app.raw_db()) as db:
        rows = db.execute("SELECT provider, subject, email FROM users").fetchall()
    assert len(rows) == 1 and rows[0]["subject"] == "ak-sub-123"
    assert rows[0]["email"] == "alice@example.com"


def test_oidc_same_sub_changed_email_keeps_one_identity(oidc_app):
    c = oidc_app.app.test_client()
    c.get("/api/auth/oidc/callback?state=s&code=c")
    # Same sub, new email (e.g. the user changed it at the IdP): still one row.
    _FakeOIDCClient.claims = {"sub": "ak-sub-123", "email": "alice@new.example.com",
                              "name": "Alice", "groups": ["crl-users"]}
    try:
        c.get("/api/auth/oidc/callback?state=s&code=c")
        with __import__("contextlib").closing(oidc_app.raw_db()) as db:
            rows = db.execute("SELECT subject, email FROM users").fetchall()
        assert len(rows) == 1
        assert rows[0]["email"] == "alice@new.example.com"
    finally:
        _FakeOIDCClient.claims = {"sub": "ak-sub-123", "email": "alice@example.com",
                                  "name": "Alice", "groups": ["crl-users"]}


def test_oidc_group_allowlist_denies_non_members(tmp_path, monkeypatch):
    mod = load_app(tmp_path, monkeypatch, {
        "CRL_OIDC_ISSUER": "https://idp.example.com/application/o/crl/",
        "CRL_OIDC_CLIENT_ID": "cid", "CRL_OIDC_CLIENT_SECRET": "csecret",
        "CRL_SESSION_SECRET": "z" * 40, "CRL_SESSION_COOKIE_SECURE": "false",
        "CRL_OIDC_ALLOWED_GROUPS": "admins-only",   # the fake user is not in this
    })
    monkeypatch.setattr(mod, "_oidc_client", lambda: _FakeOIDCClient())
    c = mod.app.test_client()
    r = c.get("/api/auth/oidc/callback?state=s&code=c")
    assert r.status_code == 302 and "auth_error=1" in r.headers["Location"]
    assert c.get("/api/auth/me").status_code == 401   # not signed in
    with __import__("contextlib").closing(mod.raw_db()) as db:
        assert db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0


def test_public_base_url_builds_redirect_uri(tmp_path, monkeypatch):
    mod = load_app(tmp_path, monkeypatch, {
        "CRL_OIDC_ISSUER": "https://idp.example.com/application/o/crl/",
        "CRL_OIDC_CLIENT_ID": "cid", "CRL_OIDC_CLIENT_SECRET": "csecret",
        "CRL_SESSION_SECRET": "z" * 40, "CRL_SESSION_COOKIE_SECURE": "false",
        "CRL_PUBLIC_BASE_URL": "https://crlmonitor.goodloe.xyz",
    })
    monkeypatch.setattr(mod, "_oidc_client", lambda: _FakeOIDCClient())
    mod.app.test_client().get("/api/auth/oidc/login")
    assert _FakeOIDCClient.last_redirect_uri == \
        "https://crlmonitor.goodloe.xyz/api/auth/oidc/callback"
