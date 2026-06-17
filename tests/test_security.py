"""Regression tests for the two security fixes:

  * SSRF egress validation + DNS-rebinding-safe IP pinning.
  * XSS-safe dashboard rendering (no attacker text in inline handlers).

These are intentionally narrow: they guard the exact behaviours the security
review changed, so a future edit that reintroduces either flaw fails CI.
"""
import os
import socket
import threading
import importlib.util
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "app.py")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "templates", "index.html")


@pytest.fixture(scope="module")
def m(tmp_path_factory):
    """Import app.py against a throwaway database, directly exposed (no proxy)."""
    d = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(d)
    os.environ["DB_PATH"] = str(d / "test.db")
    os.environ["TRUSTED_PROXY_HOPS"] = "0"
    spec = importlib.util.spec_from_file_location("crl_app_under_test", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# SSRF: validation blocks dangerous destinations and returns a pinned IP
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_dns(monkeypatch, m):
    """Resolve test hostnames deterministically, without real DNS."""
    table = {
        "public.test": "93.184.216.34",
        "rebind.test": "127.0.0.1",          # pretends to be public, points to loopback
        "metadata.test": "169.254.169.254",
        "private.test": "10.1.2.3",
    }

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in table:
            raise socket.gaierror(f"no such host: {host}")
        ip = table[host]
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))]

    monkeypatch.setattr(m.socket, "getaddrinfo", fake_getaddrinfo)
    return table


def test_validate_returns_host_and_pinned_ip(fake_dns, m):
    host, ip = m.validate_outbound_url("http://public.test/ca.crl")
    assert host == "public.test"
    assert ip == "93.184.216.34"


@pytest.mark.parametrize("url", [
    "http://rebind.test/x",       # resolves to loopback
    "http://metadata.test/x",     # cloud metadata
    "http://private.test/x",      # RFC1918 (blocked by default)
    "ftp://public.test/x",        # non-http scheme
    "http:///nohost",             # missing host
    "",                           # empty
])
def test_validate_blocks_unsafe(fake_dns, m, url):
    with pytest.raises(m.UnsafeURLError):
        m.validate_outbound_url(url)


# --------------------------------------------------------------------------- #
# SSRF: the pinned adapter connects to the vetted IP, preserving Host/TLS name
# --------------------------------------------------------------------------- #
def test_pinned_adapter_rewrites_host_keeps_host_header(m):
    import requests
    adapter = m._PinnedIPAdapter("example.com", "93.184.216.34", is_https=False)
    req = requests.Request("GET", "http://example.com:8080/ca.crl").prepare()

    captured = {}
    orig_send = requests.adapters.HTTPAdapter.send

    def fake_parent_send(self, request, **kwargs):
        captured["url"] = request.url
        captured["host"] = request.headers.get("Host")

        class _Resp:
            status_code = 200
            content = b""
        return _Resp()

    requests.adapters.HTTPAdapter.send = fake_parent_send
    try:
        adapter.send(req)
    finally:
        requests.adapters.HTTPAdapter.send = orig_send

    assert captured["url"] == "http://93.184.216.34:8080/ca.crl"
    assert captured["host"] == "example.com:8080"


def test_pinned_adapter_tls_kwargs_only_for_https(m):
    https = m._PinnedIPAdapter("h.test", "1.2.3.4", is_https=True)
    http = m._PinnedIPAdapter("h.test", "1.2.3.4", is_https=False)
    assert https.poolmanager.connection_pool_kw.get("server_hostname") == "h.test"
    assert https.poolmanager.connection_pool_kw.get("assert_hostname") == "h.test"
    # Plain-HTTP pools reject those kwargs, so they must NOT be set there.
    assert "server_hostname" not in http.poolmanager.connection_pool_kw
    assert "assert_hostname" not in http.poolmanager.connection_pool_kw


def test_pinned_request_end_to_end(monkeypatch, m):
    """A real pinned request reaches the vetted IP with the right Host header."""
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # Allow loopback just for this test so validation lets the request through.
    monkeypatch.setattr(m, "CRL_ALLOWED_HOSTS", ["127.0.0.1"])
    try:
        host, ip = m.validate_outbound_url(f"http://127.0.0.1:{port}/ca.crl")
        resp = m._pinned_request("GET", f"http://127.0.0.1:{port}/ca.crl", host, ip,
                                 timeout=5, allow_redirects=False)
        assert resp.status_code == 200
        assert resp.text == "ok"
        assert seen["host"] == f"127.0.0.1:{port}"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- #
# XSS: the dashboard must not interpolate attacker text into inline handlers
# --------------------------------------------------------------------------- #
def test_template_has_no_alias_in_inline_handlers():
    html = open(TEMPLATE_PATH, encoding="utf-8").read()
    # The vulnerable pattern embedded cert_alias in a single-quoted JS string
    # inside an onclick attribute, where HTML-entity decoding undid the escape.
    assert "cert_alias)}')" not in html
    assert "esc(r.cert_alias)}'" not in html
    # Handlers should pass only the integer id and resolve the alias from state.
    assert "aliasFor" in html
    assert "showHist(${r.id})" in html
    assert "delRow(${r.id})" in html


def test_crl_issuer_is_escaped_in_crl_data_view():
    """The CRL issuer DN is attacker-influenced (the CRL is fetched from a
    distribution point), so it must reach the DOM only through esc(). Guards
    issue #11."""
    html = open(TEMPLATE_PATH, encoding="utf-8").read()
    # Rendered through esc() at the call site, exactly once (issue #10).
    assert "esc(crlIssuerCN(d.crl_issuer))" in html
    # The helper itself must not pre-escape (double-escaping) nor must the field
    # ever be interpolated raw.
    assert "return esc(" not in html.split("function crlIssuerCN")[1].split("}")[0]
    assert "${d.crl_issuer}" not in html
    assert "${crlIssuerCN(d.crl_issuer)}" not in html
    # The CRL number is likewise escaped.
    assert "esc(d.crl_number" in html


def test_crl_snapshot_insert_is_parameterized():
    """Snapshot writes must bind CRL-derived values as parameters, never format
    them into the SQL string. Guards issue #12."""
    src = open(APP_PATH, encoding="utf-8").read()
    # The INSERT lists the columns and uses only ? placeholders for VALUES.
    assert "INSERT INTO crl_snapshots" in src
    assert "VALUES (?,?,?,?,?,?,?,?,?)" in src
    # No f-string / %-format / .format INSERT into the snapshots table.
    assert 'f"INSERT INTO crl_snapshots' not in src
    assert "f'INSERT INTO crl_snapshots" not in src
    assert "%" not in src.split("INSERT INTO crl_snapshots")[1].split(")", 1)[0]


def test_alias_round_trips_as_json_data(m):
    """A quote-laden alias is stored/returned verbatim as JSON (not HTML),
    so rendering safety stays a client concern and the data path isn't mangled."""
    client = m.app.test_client()
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    payload = {
        "cert_alias": "evil',alert(1),'",
        "cert_pem": pem,
        "issuer_pem": pem,
    }
    r = client.post("/api/monitors", json=payload,
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 201, r.get_data(as_text=True)
    assert r.get_json()["cert_alias"] == "evil',alert(1),'"


def test_mutation_requires_csrf_header(m):
    """State-changing API calls without X-Requested-With are rejected."""
    client = m.app.test_client()
    r = client.post("/api/monitors", json={"cert_alias": "x"})
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Push URL: real value in the detail view (verifiable/clonable), masked in list
# --------------------------------------------------------------------------- #
def _csrf():
    return {"X-Requested-With": "XMLHttpRequest"}


def _make_monitor(client, **extra):
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    payload = {"cert_alias": "kuma-test", "cert_pem": pem, "issuer_pem": pem}
    payload.update(extra)
    r = client.post("/api/monitors", json=payload, headers=_csrf())
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["id"]


def test_push_url_visible_in_detail_masked_in_list(m):
    client = m.app.test_client()
    url = "https://status.example.com/api/push/SECRETTOKEN"
    rid = _make_monitor(client, uptime_kuma_url=url)

    detail = client.get(f"/api/monitors/{rid}").get_json()
    assert detail["uptime_kuma_url"] == url  # verbatim, for verify/clone

    listed = next(x for x in client.get("/api/monitors").get_json() if x["id"] == rid)
    assert "SECRETTOKEN" not in listed["uptime_kuma_url"]  # masked in bulk list


def test_max_crl_bytes_setting_round_trips(m):
    """The CRL download cap is a runtime setting: exposed, updatable, and
    non-positive/garbage values fall back to the MAX_CRL_BYTES default."""
    client = m.app.test_client()

    assert "max_crl_bytes" in client.get("/api/settings").get_json()

    r = client.put("/api/settings", json={"max_crl_bytes": 50 * 1024 * 1024},
                   headers=_csrf())
    assert r.status_code == 200
    assert int(r.get_json()["max_crl_bytes"]) == 50 * 1024 * 1024

    # 0 / invalid -> default, never an unusable cap.
    r = client.put("/api/settings", json={"max_crl_bytes": 0}, headers=_csrf())
    assert int(r.get_json()["max_crl_bytes"]) == m.MAX_CRL_BYTES


def test_resolve_max_crl_bytes_reads_setting(m):
    from contextlib import closing
    with closing(m.raw_db()) as db:
        db.execute(
            "INSERT INTO settings (key, value) VALUES ('max_crl_bytes', '987654') "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        db.commit()
        assert m.resolve_max_crl_bytes(db) == 987654
        db.execute("UPDATE settings SET value='nonsense' WHERE key='max_crl_bytes'")
        db.commit()
        assert m.resolve_max_crl_bytes(db) == m.MAX_CRL_BYTES


def test_schedule_settings_round_trip(m):
    """Global scheduling defaults are exposed and updatable; an unknown mode
    falls back to 'frequency'."""
    client = m.app.test_client()
    s = client.get("/api/settings").get_json()
    assert s["default_schedule_mode"] in ("frequency", "next_update")
    assert "default_safety_window_min" in s

    r = client.put("/api/settings",
                   json={"default_schedule_mode": "next_update",
                         "default_safety_window_min": 120}, headers=_csrf())
    assert r.status_code == 200
    out = r.get_json()
    assert out["default_schedule_mode"] == "next_update"
    assert int(out["default_safety_window_min"]) == 120

    r = client.put("/api/settings", json={"default_schedule_mode": "bogus"},
                   headers=_csrf())
    assert r.get_json()["default_schedule_mode"] == "frequency"


def test_monitor_schedule_fields_round_trip(m):
    """Per-monitor schedule_mode / safety_window_min persist; an unknown mode
    normalizes to None (inherit the global default)."""
    client = m.app.test_client()
    rid = _make_monitor(client, schedule_mode="next_update", safety_window_min=45)
    d = client.get(f"/api/monitors/{rid}").get_json()
    assert d["schedule_mode"] == "next_update"
    assert d["safety_window_min"] == 45

    rid2 = _make_monitor(client, schedule_mode="nope")
    d2 = client.get(f"/api/monitors/{rid2}").get_json()
    assert d2["schedule_mode"] is None


def test_retry_and_retention_settings_round_trip(m):
    client = m.app.test_client()
    s = client.get("/api/settings").get_json()
    for k in ("default_retry_min", "retry_backoff", "retry_max_min",
              "crl_data_retention_days"):
        assert k in s

    r = client.put("/api/settings", json={
        "default_retry_min": 9, "retry_backoff": True,
        "retry_max_min": 240, "crl_data_retention_days": 30,
    }, headers=_csrf())
    assert r.status_code == 200
    out = r.get_json()
    assert int(out["default_retry_min"]) == 9
    assert out["retry_backoff"] is True
    assert int(out["retry_max_min"]) == 240
    assert int(out["crl_data_retention_days"]) == 30


def test_monitor_retry_min_round_trips(m):
    client = m.app.test_client()
    rid = _make_monitor(client, retry_min=3)
    assert client.get(f"/api/monitors/{rid}").get_json()["retry_min"] == 3


def test_show_test_pills_setting_round_trips(m):
    """The dashboard 'show tests that were run' toggle is exposed, defaults on,
    and persists, and the template gates the pills on it."""
    client = m.app.test_client()
    s = client.get("/api/settings").get_json()
    assert s.get("show_test_pills") is True  # default on

    r = client.put("/api/settings", json={"show_test_pills": False}, headers=_csrf())
    assert r.status_code == 200
    assert r.get_json()["show_test_pills"] is False
    assert client.get("/api/settings").get_json()["show_test_pills"] is False

    html = open(TEMPLATE_PATH, encoding="utf-8").read()
    assert "if (!showTestPills" in html  # pills gated on the toggle


def test_outage_exclusion_persists_and_affects_uptime(m):
    """An outage can be excluded from (and re-included in) the uptime
    calculation, and the choice is persisted on the history row."""
    from contextlib import closing
    from datetime import datetime, timedelta, timezone
    client = m.app.test_client()
    rid = _make_monitor(client)
    now = datetime.now(timezone.utc)

    # A bounded Error outage [now-2h, now-1h] between Valid spans.
    with closing(m.raw_db()) as db:
        for status, dt in (("Valid", now - timedelta(hours=4)),
                           ("Error", now - timedelta(hours=2)),
                           ("Valid", now - timedelta(hours=1))):
            db.execute(
                "INSERT INTO history (monitor_id, status, message, timestamp) "
                "VALUES (?,?,?,?)", (rid, status, "x", dt.isoformat()))
        db.commit()
        hid = db.execute(
            "SELECT id FROM history WHERE monitor_id=? AND status='Error'",
            (rid,)).fetchone()["id"]

    qs = (f"?from={(now - timedelta(hours=3)).isoformat()}"
          f"&to={now.isoformat()}&monitor_ids={rid}")

    rep = client.get("/api/reports/uptime" + qs).get_json()["monitors"][0]
    assert rep["down_seconds"] > 0
    assert rep["uptime_pct"] < 100

    # Exclude the outage -> dropped from the calculation, persisted on the row.
    r = client.put(f"/api/history/{hid}/exclude", json={"excluded": True},
                   headers=_csrf())
    assert r.status_code == 200 and r.get_json()["uptime_excluded"] is True

    rep = client.get("/api/reports/uptime" + qs).get_json()["monitors"][0]
    assert rep["down_seconds"] == 0
    assert rep["excluded_seconds"] > 0
    assert rep["uptime_pct"] == 100
    # The downtime is still listed, flagged as user-excluded.
    assert rep["downtimes"][0]["user_excluded"] is True

    # Re-include -> back to counting against uptime.
    client.put(f"/api/history/{hid}/exclude", json={"excluded": False}, headers=_csrf())
    rep = client.get("/api/reports/uptime" + qs).get_json()["monitors"][0]
    assert rep["down_seconds"] > 0 and rep["uptime_pct"] < 100


def test_crl_data_endpoint_returns_snapshots(m):
    client = m.app.test_client()
    rid = _make_monitor(client)  # dummy PEM -> the check errors, but still snapshots
    client.post(f"/api/monitors/{rid}/check", headers=_csrf())
    data = client.get(f"/api/monitors/{rid}/crl-data").get_json()
    assert isinstance(data, list) and len(data) >= 1
    assert "captured_at" in data[0] and "status" in data[0]


def test_update_push_url_is_authoritative(m):
    client = m.app.test_client()
    url = "https://status.example.com/api/push/TOK1"
    rid = _make_monitor(client, uptime_kuma_url=url)

    # Omitting the key keeps the stored value.
    client.put(f"/api/monitors/{rid}", json={"frequency_min": 30}, headers=_csrf())
    assert client.get(f"/api/monitors/{rid}").get_json()["uptime_kuma_url"] == url

    # An explicit empty value clears it (what you see is what's saved).
    client.put(f"/api/monitors/{rid}", json={"uptime_kuma_url": ""}, headers=_csrf())
    assert client.get(f"/api/monitors/{rid}").get_json()["uptime_kuma_url"] == ""


def test_kuma_push_reports_outcome(m, monkeypatch):
    """push_to_uptime_kuma returns a token reflecting the real outcome: ok only
    on 200 {"ok":true}, otherwise failed/error/blocked, and None with no URL."""
    import requests

    class Resp:
        def __init__(self, code, body):
            self.status_code, self._b = code, body
        def json(self):
            import json as _j
            return _j.loads(self._b)

    monkeypatch.setattr(m, "validate_outbound_url", lambda u: ("h", "203.0.113.5"))
    url = "https://status.example.com/api/push/TOK"

    monkeypatch.setattr(m, "_pinned_request", lambda *a, **k: Resp(200, '{"ok":true}'))
    assert m.push_to_uptime_kuma(url, "Valid", "m", False) == "ok"

    monkeypatch.setattr(m, "_pinned_request", lambda *a, **k: Resp(200, '{"ok":false}'))
    assert m.push_to_uptime_kuma(url, "Valid", "m", False) == "failed"

    monkeypatch.setattr(m, "_pinned_request", lambda *a, **k: Resp(404, 'nope'))
    assert m.push_to_uptime_kuma(url, "Valid", "m", False) == "failed"

    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("x")
    monkeypatch.setattr(m, "_pinned_request", boom)
    assert m.push_to_uptime_kuma(url, "Valid", "m", False) == "error"

    def block(u):
        raise m.UnsafeURLError("private")
    monkeypatch.setattr(m, "validate_outbound_url", block)
    assert m.push_to_uptime_kuma(url, "Valid", "m", False) == "blocked"

    assert m.push_to_uptime_kuma("", "Valid", "m", False) is None


def test_check_persists_and_returns_kuma_push_outcome(m, monkeypatch):
    """A manual check records the push outcome on the monitor and returns it."""
    monkeypatch.setattr(m, "push_to_uptime_kuma", lambda *a, **k: "ok")
    client = m.app.test_client()
    rid = _make_monitor(client,
                        uptime_kuma_url="https://status.example.com/api/push/TOK")
    r = client.post(f"/api/monitors/{rid}/check", headers=_csrf())
    assert r.status_code == 200
    assert r.get_json()["last_kuma_push"] == "ok"
