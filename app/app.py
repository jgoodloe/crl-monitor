"""
CRL Monitor — single-container edition.

A Flask app that serves both the JSON API and the web UI from one process on
one port, with no separate frontend/backend services and no external database.
Designed to sit cleanly behind a reverse proxy (nginx, Traefik, NPM, pfSense)
including under a URL subpath, and to manage fewer than ~30 monitored
certificates / CRLs.

State is stored in SQLite. Checks run on a background scheduler thread using
the `cryptography` library to download and verify real X.509 CRLs (no shelling
out to the openssl binary). For each monitored certificate the app resolves a
CRL distribution point (an explicit override, or the cert's CRLDistributionPoints
extension), downloads the CRL, verifies its signature against the issuer, checks
its thisUpdate/nextUpdate freshness, and looks up the certificate's serial in the
revoked list.
"""

import os
import json
import socket
import ipaddress
import sqlite3
import threading
import time
import logging
from contextlib import closing
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit

import requests
from flask import (
    Flask, request, jsonify, g, render_template
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, ed25519, ed448

# --------------------------------------------------------------------------- #
# Configuration (all via environment variables)
# --------------------------------------------------------------------------- #
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "crl_monitor.db"))
PORT = int(os.environ.get("PORT", "8080"))
# URL prefix for running behind a reverse proxy subpath, e.g. "/crl".
URL_PREFIX = os.environ.get("URL_PREFIX", "").rstrip("/")
# How often (seconds) the scheduler wakes up to look for due checks.
SCHEDULER_INTERVAL = int(os.environ.get("SCHEDULER_INTERVAL", "30"))
# Per-request CRL HTTP timeout (seconds).
CRL_TIMEOUT = int(os.environ.get("CRL_TIMEOUT", "30"))
# Number of history rows retained per monitor.
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", "200"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


def _env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# --- SSRF egress controls --------------------------------------------------- #
# Block RFC 1918 / unique-local (private) destinations. Loopback, link-local
# (incl. 169.254 cloud-metadata), multicast, reserved and unspecified addresses
# are ALWAYS blocked regardless of this flag. Internal-PKI deployments that
# legitimately fetch CRLs from private hosts can set this false (and/or use
# CRL_ALLOWED_HOSTS to permit specific hosts/CIDRs).
CRL_BLOCK_PRIVATE = _env_bool("CRL_BLOCK_PRIVATE", True)
# Comma-separated hostnames, IPs, or CIDRs that bypass the private-range block.
CRL_ALLOWED_HOSTS = [
    h.strip() for h in os.environ.get("CRL_ALLOWED_HOSTS", "").split(",") if h.strip()
]

# --- Reverse-proxy trust ---------------------------------------------------- #
# Number of proxy hops to trust for X-Forwarded-* headers. 0 disables ProxyFix
# entirely (correct when the app is exposed directly, not behind a proxy).
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))

# --- Abuse / resource limits ------------------------------------------------ #
# Max accepted size (bytes) for each PEM field.
MAX_PEM_BYTES = int(os.environ.get("MAX_PEM_BYTES", "32768"))
# Max number of monitors that may exist (0 = unlimited).
MAX_MONITORS = int(os.environ.get("MAX_MONITORS", "100"))
# Max CRL download size (bytes). CRLs can be large; cap the download so a
# hostile/huge endpoint can't exhaust memory. Default 16 MiB.
MAX_CRL_BYTES = int(os.environ.get("MAX_CRL_BYTES", str(16 * 1024 * 1024)))
# Token-bucket rate limits per client IP (requests per minute; 0 = unlimited).
RATE_LIMIT_MUTATE = int(os.environ.get("RATE_LIMIT_MUTATE", "60"))
RATE_LIMIT_CHECK = int(os.environ.get("RATE_LIMIT_CHECK", "20"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("crl-monitor")

os.makedirs(DATA_DIR, exist_ok=True)

# --------------------------------------------------------------------------- #
# Selectable verification tests
# --------------------------------------------------------------------------- #
# Each CRL check always performs the foundational steps (resolve a CRL URL,
# reach the distribution point, get HTTP 200, parse the CRL) because without
# them there is nothing to evaluate. Beyond that, these named tests can be
# individually enabled per monitor (or via a global default).
FOUNDATIONAL_TESTS = [
    ("cert_load",  "Certificate & issuer load"),
    ("crl_url",    "CRL URL available"),
    ("reachable",  "CRL distribution point reachable"),
    ("http_200",   "HTTP 200 response"),
    ("crl_parse",  "CRL parses (DER/PEM)"),
]
EVAL_TESTS = [
    ("cert_status",   "Certificate revocation status (not revoked)"),
    ("crl_signature", "CRL signature verification"),
    ("issuer_match",  "CRL issuer matches the issuer certificate"),
    ("this_update",   "thisUpdate sanity (present, not future-dated)"),
    ("next_update",   "nextUpdate freshness (present, not in the past)"),
    ("response_time", "Response-time threshold (download under the limit)"),
]
# Foundational tests are prerequisites in a chain (each enables the next); when
# one fails the check cannot continue and dependent tests are skipped. Whether
# that failure marks the monitor as an error depends on whether the test is
# selected — deselect it and its failure is recorded but no longer fails the
# status. They default ON, preserving the obvious behaviour. Evaluation tests
# inspect a successfully parsed CRL.
TESTS = FOUNDATIONAL_TESTS + EVAL_TESTS
ALL_TEST_KEYS = [k for k, _ in TESTS]
TEST_LABELS = dict(TESTS)
FOUNDATIONAL_KEYS = [k for k, _ in FOUNDATIONAL_TESTS]


def test_group(key):
    return "foundational" if key in FOUNDATIONAL_KEYS else "evaluation"


# Default set for new installs: every foundational step, plus the evaluation
# tests except `response_time` (depends on a threshold). It is opt-in.
DEFAULT_TESTS = FOUNDATIONAL_KEYS + [
    "cert_status", "crl_signature", "issuer_match", "this_update", "next_update",
]
# Fallback response-time threshold (ms) when neither monitor nor global set.
DEFAULT_RESPONSE_TIME_MS = 5000

# --------------------------------------------------------------------------- #
# Scheduling modes
# --------------------------------------------------------------------------- #
# "frequency"   — re-check every `frequency_min` minutes (the classic behaviour).
# "next_update" — re-check shortly after the CRL's own nextUpdate, i.e. at
#                 nextUpdate + a safety window (minutes) to allow for the CA
#                 publishing the fresh CRL and for propagation. Falls back to the
#                 frequency interval when the CRL has no usable nextUpdate or the
#                 computed time is already in the past.
SCHEDULE_FREQUENCY = "frequency"
SCHEDULE_NEXT_UPDATE = "next_update"
SCHEDULE_MODES = (SCHEDULE_FREQUENCY, SCHEDULE_NEXT_UPDATE)
DEFAULT_SCHEDULE_MODE = SCHEDULE_FREQUENCY
# Fallback safety window (minutes) added after nextUpdate when neither monitor
# nor global sets one.
DEFAULT_SAFETY_WINDOW_MIN = 60


def parse_tests(value):
    """Parse a stored tests value into a clean list of known test keys.

    Returns None to mean "not set" (inherit the global default). Accepts a JSON
    array string or a comma-separated string; unknown keys are dropped and
    original ordering (per ALL_TEST_KEYS) is preserved.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        s = str(value).strip()
        if s == "":
            return None
        try:
            parsed = json.loads(s)
            items = parsed if isinstance(parsed, list) else [parsed]
        except (ValueError, TypeError):
            items = [p.strip() for p in s.split(",")]
    selected = {str(i).strip() for i in items}
    return [k for k in ALL_TEST_KEYS if k in selected]


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_alias      TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    issuer_pem      TEXT NOT NULL,
    crl_uri         TEXT NOT NULL DEFAULT '',
    frequency_min   INTEGER NOT NULL DEFAULT 60,
    enabled         INTEGER NOT NULL DEFAULT 1,
    uptime_kuma_url TEXT NOT NULL DEFAULT '',
    tests           TEXT,
    response_time_ms INTEGER,
    -- NULL on both => inherit the global scheduling defaults.
    schedule_mode    TEXT,
    safety_window_min INTEGER,
    last_checks     TEXT,
    last_run        TEXT,
    next_run        TEXT,
    status          TEXT NOT NULL DEFAULT 'Unknown',
    last_message    TEXT NOT NULL DEFAULT 'Configuration created.',
    response_ms     INTEGER,
    this_update     TEXT,
    next_update     TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id   INTEGER NOT NULL,
    status       TEXT NOT NULL,
    message      TEXT NOT NULL DEFAULT '',
    timestamp    TEXT NOT NULL,
    comment      TEXT,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_history_monitor
    ON history(monitor_id, timestamp DESC);

-- Audit log of enable/disable (and create) events, used both for the audit
-- trail and to exclude "disabled" periods from uptime reports.
CREATE TABLE IF NOT EXISTS audit_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id   INTEGER NOT NULL,
    event        TEXT NOT NULL,          -- 'enabled' | 'disabled' | 'created'
    timestamp    TEXT NOT NULL,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_monitor
    ON audit_events(monitor_id, timestamp);

-- Operator-defined maintenance windows excluded from uptime calculations.
-- monitor_id NULL means the window applies to every monitor.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id   INTEGER,
    start_ts     TEXT NOT NULL,
    end_ts       TEXT NOT NULL,
    comment      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_maint_monitor
    ON maintenance_windows(monitor_id, start_ts);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "debug_logging": "false",
    "log_only_failures": "false",
    "uptime_kuma_logging": "true",
    # Global default set of verification tests, applied to any monitor that
    # does not specify its own. Stored as comma-separated test keys.
    "default_tests": ",".join(DEFAULT_TESTS),
    # Global default response-time threshold (ms) for the response_time test,
    # used by any monitor that doesn't set its own.
    "default_response_time_ms": str(DEFAULT_RESPONSE_TIME_MS),
    # Global default scheduling mode ("frequency" | "next_update") and the safety
    # window (minutes) added after a CRL's nextUpdate in next_update mode. Applied
    # to any monitor that doesn't set its own.
    "default_schedule_mode": DEFAULT_SCHEDULE_MODE,
    "default_safety_window_min": str(DEFAULT_SAFETY_WINDOW_MIN),
    # Maximum accepted CRL download size (bytes). Configurable at runtime so an
    # operator can raise it for large CRLs (e.g. some US-government CAs publish
    # CRLs of tens of MiB). Defaults to the MAX_CRL_BYTES env value.
    "max_crl_bytes": str(MAX_CRL_BYTES),
}


def get_db():
    """Per-request connection (also usable standalone via closing())."""
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


def raw_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(db):
    """Add columns introduced after the initial schema to pre-existing DBs.

    CREATE TABLE IF NOT EXISTS won't alter an existing table, so additive
    columns are applied here. Each is nullable, so old rows simply inherit the
    global defaults until edited."""
    have = {r["name"] for r in db.execute("PRAGMA table_info(monitors)").fetchall()}
    for col, ddl in (
        ("schedule_mode", "ALTER TABLE monitors ADD COLUMN schedule_mode TEXT"),
        ("safety_window_min", "ALTER TABLE monitors ADD COLUMN safety_window_min INTEGER"),
    ):
        if col not in have:
            db.execute(ddl)


def init_db():
    with closing(raw_db()) as db:
        db.executescript(SCHEMA)
        _migrate(db)
        for k, v in DEFAULT_SETTINGS.items():
            db.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (k, v),
            )
        db.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_setting(db, key, default="false"):
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def add_audit(db, monitor_id, event, ts=None):
    """Record an enable/disable/create event for a monitor."""
    db.execute(
        "INSERT INTO audit_events (monitor_id, event, timestamp) VALUES (?, ?, ?)",
        (monitor_id, event, ts or now_iso()),
    )


# --------------------------------------------------------------------------- #
# Outbound URL safety (SSRF egress controls)
# --------------------------------------------------------------------------- #
class UnsafeURLError(ValueError):
    """Raised when an outbound URL is rejected by the egress policy."""


def _host_in_allowlist(hostname, ip):
    """True if the hostname or resolved IP matches a CRL_ALLOWED_HOSTS entry."""
    for entry in CRL_ALLOWED_HOSTS:
        if hostname and hostname.lower() == entry.lower():
            return True
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass  # entry was a hostname, not a CIDR/IP
    return False


def validate_outbound_url(url):
    """Validate a URL we are about to fetch server-side.

    Enforces an http/https scheme and rejects addresses that should never be
    reached from the server: loopback, link-local (incl. 169.254 cloud
    metadata), multicast, reserved and unspecified are always blocked; private
    / unique-local are blocked when CRL_BLOCK_PRIVATE is set, unless the host
    is explicitly allowlisted. Returns (hostname, pinned_ip) — the caller must
    connect to pinned_ip so the host cannot re-resolve to a blocked address
    after this check (DNS rebinding). Raises UnsafeURLError.
    """
    if not url or not url.strip():
        raise UnsafeURLError("empty URL")
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ("http", "https"):
        raise UnsafeURLError("scheme must be http or https")
    hostname = parts.hostname
    if not hostname:
        raise UnsafeURLError("missing host")

    # Resolve every address the host maps to and check each one.
    try:
        infos = socket.getaddrinfo(hostname, parts.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeURLError(f"hostname does not resolve: {e}")

    seen = set()
    validated = []
    for info in infos:
        addr = info[4][0].split("%")[0]  # strip any IPv6 zone id
        if addr in seen:
            continue
        seen.add(addr)
        ip = ipaddress.ip_address(addr)
        allowed = _host_in_allowlist(hostname, ip)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast \
                or ip.is_reserved or ip.is_unspecified:
            if not allowed:
                raise UnsafeURLError(f"destination {addr} is not permitted")
        elif ip.is_private and CRL_BLOCK_PRIVATE and not allowed:
            raise UnsafeURLError(f"destination {addr} is in a private range")
        validated.append(addr)
    if not validated:
        raise UnsafeURLError("hostname does not resolve to any address")
    # Pin to an address we just validated. The caller dials this IP directly so
    # a hostile resolver can't swap in a blocked address between now and the
    # request (DNS rebinding).
    return hostname, validated[0]


# --------------------------------------------------------------------------- #
# Outbound fetch pinned to a pre-validated IP (DNS-rebinding safe)
# --------------------------------------------------------------------------- #
class _PinnedIPAdapter(requests.adapters.HTTPAdapter):
    """Connect only to the IP that validate_outbound_url() already vetted.

    The request URL's host is rewritten to the pinned IP so no second DNS
    lookup happens, while the original Host header (and, for TLS, the SNI /
    certificate hostname) is preserved so virtual hosting and cert verification
    still behave normally.
    """

    def __init__(self, hostname, pinned_ip, is_https, **kwargs):
        self._hostname = hostname
        self._pinned_ip = pinned_ip
        self._is_https = is_https
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self._is_https:
            # Verify the cert against, and send SNI for, the real hostname even
            # though the socket connects to the pinned IP. (These pool kwargs
            # are only valid for HTTPS pools, hence the scheme guard.)
            kwargs["assert_hostname"] = self._hostname
            kwargs["server_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)

    def send(self, request, **kwargs):
        parts = urlsplit(request.url)
        if (parts.hostname or "").lower() == self._hostname.lower():
            host_header = parts.netloc  # original host[:port], for the Host hdr
            netloc = f"[{self._pinned_ip}]" if ":" in self._pinned_ip else self._pinned_ip
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            request.url = parts._replace(netloc=netloc).geturl()
            request.headers["Host"] = host_header
        return super().send(request, **kwargs)


def _pinned_request(method, url, hostname, pinned_ip, **kwargs):
    """Issue a request that connects only to `pinned_ip` for `hostname`."""
    scheme = urlsplit(url).scheme.lower()
    adapter = _PinnedIPAdapter(hostname, pinned_ip, scheme == "https")
    with requests.Session() as session:
        session.mount(f"{scheme}://", adapter)
        return session.request(method, url, **kwargs)


# --------------------------------------------------------------------------- #
# CRL check core (uses `cryptography`, not the openssl CLI)
# --------------------------------------------------------------------------- #
class CRLResult:
    def __init__(self, status, message, response_ms=None,
                 this_update=None, next_update=None, checks=None):
        self.status = status            # Valid | Revoked | Error | Unknown
        self.message = message
        self.response_ms = response_ms
        self.this_update = this_update
        self.next_update = next_update
        # Per-test outcomes: list of {key, label, status, message} where status
        # is one of pass | fail | skip.
        self.checks = checks or []


def _load_cert(pem_text, label):
    pem_bytes = pem_text.strip().encode("utf-8")
    if b"BEGIN CERTIFICATE" not in pem_bytes:
        raise ValueError(f"{label} is not valid PEM (missing BEGIN CERTIFICATE).")
    return x509.load_pem_x509_certificate(pem_bytes)


def _crl_urls_from_cert(cert):
    """Pull http/https CRL distribution point URLs from the cert's CDP extension."""
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
    except x509.ExtensionNotFound:
        return urls
    for dp in cdp:
        for name in (dp.full_name or []):
            if isinstance(name, x509.UniformResourceIdentifier):
                v = name.value
                if v and v.lower().startswith(("http://", "https://")):
                    urls.append(v)
    return urls


def _load_crl(content):
    """Parse CRL bytes as DER, falling back to PEM."""
    try:
        return x509.load_der_x509_crl(content)
    except Exception:
        return x509.load_pem_x509_crl(content)


# Allow a little clock skew before calling a thisUpdate "future-dated".
_CLOCK_SKEW = timedelta(minutes=5)


def _aware(dt):
    """Return a timezone-aware UTC datetime (treat naive as UTC)."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _pubkey_verify(cert, signature, data, hash_alg):
    """Verify `signature` over `data` using `cert`'s public key.

    Raises InvalidSignature on mismatch, or ValueError for unsupported keys.
    """
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, data, padding.PKCS1v15(), hash_alg)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pub.verify(signature, data)  # Ed* carry their own hash
    else:
        raise ValueError(f"unsupported key type {type(pub).__name__}")


def _verify_crl_signature(crl, issuer):
    """Verify the CRL signature against the issuer certificate. Returns
    (ok, message)."""
    try:
        _pubkey_verify(issuer, crl.signature, crl.tbs_certlist_bytes,
                       crl.signature_hash_algorithm)
        return True, "CRL signature verified against the issuer certificate."
    except InvalidSignature:
        return False, "CRL signature does not verify against the issuer certificate."
    except Exception as e:
        return False, f"CRL signature could not be verified ({e})."


def _crl_update_window(crl):
    """Return (last_update, next_update) as aware UTC datetimes."""
    try:
        lu, nu = crl.last_update_utc, crl.next_update_utc
    except AttributeError:  # older cryptography
        lu, nu = crl.last_update, crl.next_update
    return _aware(lu), _aware(nu)


def _evaluate_tests(enabled, crl, this_update, next_update, issuer, cert,
                    elapsed_ms=None, threshold_ms=0):
    """Run the enabled selectable tests against a successfully parsed CRL.

    Returns (checks, revoked) where `revoked` is True when the certificate's
    serial appears in the CRL's revoked list.
    """
    now = datetime.now(timezone.utc)
    revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    revoked = revoked_entry is not None
    checks = []

    def add(key, ok, message):
        checks.append({
            "key": key, "label": TEST_LABELS[key],
            "status": "pass" if ok else "fail", "message": message,
        })

    if "cert_status" in enabled:
        if not revoked:
            add("cert_status", True,
                "Certificate serial is not present in the CRL (not revoked).")
        else:
            try:
                rdate = revoked_entry.revocation_date_utc
            except AttributeError:
                rdate = _aware(revoked_entry.revocation_date)
            add("cert_status", False,
                f"Certificate is revoked. Revocation date: "
                f"{rdate.isoformat() if rdate else 'N/A'}.")

    if "crl_signature" in enabled:
        try:
            ok, msg = _verify_crl_signature(crl, issuer)
        except Exception as e:
            ok, msg = False, f"CRL signature could not be verified ({e})."
        add("crl_signature", ok, msg)

    if "issuer_match" in enabled:
        if crl.issuer == issuer.subject:
            add("issuer_match", True,
                "CRL issuer matches the issuer certificate's subject.")
        else:
            add("issuer_match", False,
                "CRL issuer does not match the issuer certificate's subject.")

    if "this_update" in enabled:
        if this_update is None:
            add("this_update", False, "CRL has no thisUpdate (last update) field.")
        elif this_update > now + _CLOCK_SKEW:
            add("this_update", False,
                f"thisUpdate {this_update.isoformat()} is in the future.")
        else:
            add("this_update", True, "thisUpdate is present and not future-dated.")

    if "next_update" in enabled:
        if next_update is None:
            add("next_update", False, "CRL has no nextUpdate field.")
        elif next_update < now:
            add("next_update", False,
                f"CRL is stale (nextUpdate {next_update.isoformat()} is in the past).")
        else:
            add("next_update", True, "nextUpdate is present and not in the past.")

    if "response_time" in enabled:
        limit = int(threshold_ms or 0)
        if elapsed_ms is None:
            add("response_time", False, "Response time was not measured.")
        elif limit <= 0:
            add("response_time", True,
                f"Response time {elapsed_ms} ms (no threshold configured).")
        elif elapsed_ms > limit:
            add("response_time", False,
                f"Response time {elapsed_ms} ms exceeds the {limit} ms threshold.")
        else:
            add("response_time", True,
                f"Response time {elapsed_ms} ms is within the {limit} ms threshold.")

    return checks, revoked


def _derive_status(checks, revoked):
    """Overall monitor status from the per-test check dicts."""
    failed = [c for c in checks if c["status"] == "fail"]
    cert_check = next((c for c in checks if c["key"] == "cert_status"), None)
    cert_failed = cert_check is not None and cert_check["status"] == "fail"
    if cert_failed and revoked:
        return "Revoked"
    if failed:
        return "Error"
    return "Valid"


def _compose_message(checks, enabled):
    failed = [c for c in checks if c["status"] == "fail"]
    skipped = [c for c in checks if c["status"] == "skip"]
    if not enabled:
        return "No verification tests selected."
    if failed:
        return (f"{len(failed)} of {len(enabled)} checks failed: "
                + " ".join(c["message"] for c in failed))
    if skipped:
        # A deselected prerequisite step failed: nothing failed the status, but
        # the dependent tests could not run.
        passed = len(enabled) - len(skipped)
        return (f"A prerequisite step was not met (and not selected); "
                f"{len(skipped)} dependent check(s) skipped, {passed} passed.")
    return f"All {len(enabled)} selected checks passed."


def _download_crl(url, timeout, max_bytes):
    """Validate egress, pin the IP, GET the CRL (capped). Returns
    (status_code, content, too_large). Raises UnsafeURLError / RequestException."""
    pin_host, pin_ip = validate_outbound_url(url)
    resp = _pinned_request(
        "GET", url, pin_host, pin_ip,
        headers={"Accept": "application/pkix-crl, application/x-pkcs7-crl, */*"},
        timeout=timeout, allow_redirects=False, stream=True,
    )
    try:
        status = resp.status_code
        content = b""
        too_large = False
        for chunk in resp.iter_content(65536):
            content += chunk
            if len(content) > max_bytes:
                too_large = True
                break
    finally:
        resp.close()
    return status, content, too_large


def run_crl_check(cert_pem, issuer_pem, crl_uri, enabled_tests=None,
                  timeout=CRL_TIMEOUT, threshold_ms=0, max_bytes=MAX_CRL_BYTES):
    """Resolve a CRL distribution point, download the CRL, parse it, and
    evaluate the selected verification tests.

    Every test — foundational and evaluation — is individually selectable via
    `enabled_tests` (see ALL_TEST_KEYS). The foundational steps form a
    dependency chain; when one fails the check cannot continue and the dependent
    tests are skipped. A failed foundational step only fails the overall status
    when that step is selected. `threshold_ms` is the response-time limit and
    `max_bytes` caps the CRL download size.
    """
    enabled = [k for k in ALL_TEST_KEYS if k in (enabled_tests or [])]
    enabled_set = set(enabled)
    checks = []

    def record(key, ok, message):
        """Record a foundational step's outcome, but only if it's selected."""
        if key in enabled_set:
            checks.append({"key": key, "label": TEST_LABELS[key],
                           "status": "pass" if ok else "fail", "message": message})

    def finish(response_ms=None, this_update=None, next_update=None, revoked=False):
        # Any selected test we never reached couldn't run -> skip.
        done = {c["key"] for c in checks}
        for k in enabled:
            if k not in done:
                checks.append({"key": k, "label": TEST_LABELS[k], "status": "skip",
                               "message": "Not evaluated (a prerequisite step did not pass)."})
        order = {k: i for i, k in enumerate(ALL_TEST_KEYS)}
        checks.sort(key=lambda c: order.get(c["key"], 999))
        return CRLResult(
            _derive_status(checks, revoked),
            _compose_message(checks, enabled),
            response_ms=response_ms, this_update=this_update,
            next_update=next_update, checks=checks,
        )

    start = time.monotonic()

    # 1. Load the certificate and issuer.
    try:
        cert = _load_cert(cert_pem, "Certificate")
        issuer = _load_cert(issuer_pem, "Issuer certificate")
    except Exception as e:
        log.info("[CRL] certificate load failed: %s", e)
        record("cert_load", False, "Certificate or issuer PEM could not be parsed.")
        return finish()
    record("cert_load", True, "Certificate and issuer loaded.")

    # 2. Resolve the CRL URL(s): an explicit override first, then the cert's
    #    CRLDistributionPoints extension. The cert-derived URLs are
    #    attacker-controlled too, so each is validated the same way before fetch.
    candidates = []
    if (crl_uri or "").strip():
        candidates.append(crl_uri.strip())
    for u in _crl_urls_from_cert(cert):
        if u not in candidates:
            candidates.append(u)
    if not candidates:
        record("crl_url", False,
               "No CRL URL provided and none found in the certificate's "
               "CRLDistributionPoints extension.")
        return finish()
    record("crl_url", True, "CRL URL resolved.")

    # 3. Try each candidate until one is reachable and returns HTTP 200.
    #    Redirects are disabled so an endpoint can't bounce us to an internal
    #    address that bypassed validation.
    reached_any = False
    chosen = None  # (url, status, content, too_large)
    for url in candidates:
        try:
            status, content, too_large = _download_crl(url, timeout, max_bytes)
        except UnsafeURLError as e:
            log.warning("[CRL] blocked outbound URL %r: %s", url, e)
            continue
        except requests.exceptions.RequestException as e:
            # Generic client-facing message: the detailed exception (connection
            # refused vs. timeout vs. DNS) is an SSRF reconnaissance oracle.
            log.warning("[CRL] CRL request failed for %r: %s", url, e)
            continue
        reached_any = True
        if status == 200:
            chosen = (url, status, content, too_large)
            break

    if not reached_any:
        record("reachable", False, "CRL distribution point is unreachable.")
        return finish()
    record("reachable", True, "CRL distribution point reachable.")

    if chosen is None:
        record("http_200", False, "CRL distribution point did not return HTTP 200.")
        return finish()
    record("http_200", True, "CRL distribution point returned HTTP 200.")

    url, status, content, too_large = chosen
    elapsed_ms = int((time.monotonic() - start) * 1000)

    # 4. Parse the CRL (DER, then PEM).
    if too_large:
        record("crl_parse", False,
               f"CRL exceeds the maximum download size ({max_bytes} bytes).")
        return finish(response_ms=elapsed_ms)
    try:
        crl = _load_crl(content)
    except Exception as e:
        log.info("[CRL] CRL parse failed: %s", e)
        record("crl_parse", False, "CRL could not be parsed as DER or PEM.")
        return finish(response_ms=elapsed_ms)
    record("crl_parse", True, "CRL parsed.")

    def _fmt(dt):
        return dt.isoformat() if dt else None

    this_update, next_update = _crl_update_window(crl)

    eval_checks, revoked = _evaluate_tests(
        enabled, crl, this_update, next_update, issuer, cert,
        elapsed_ms=elapsed_ms, threshold_ms=threshold_ms,
    )
    checks.extend(eval_checks)

    return finish(response_ms=elapsed_ms, this_update=_fmt(this_update),
                  next_update=_fmt(next_update), revoked=revoked)


# --------------------------------------------------------------------------- #
# Uptime Kuma passive push
# --------------------------------------------------------------------------- #
def push_to_uptime_kuma(url, status, message, logging_enabled=True):
    if not url or not url.strip():
        return
    # The push URL carries a secret token and is attacker-influenceable, so it
    # is subject to the same egress policy and is never logged in full.
    try:
        pin_host, pin_ip = validate_outbound_url(url)
    except UnsafeURLError as e:
        log.warning("[UptimeKuma] push URL blocked by egress policy: %s", e)
        return
    kuma_status = "up" if status == "Valid" else "down"
    try:
        if logging_enabled:
            log.info("[UptimeKuma] push status=%s msg=%s", kuma_status, message)
        _pinned_request(
            "GET", url, pin_host, pin_ip,
            params={"status": kuma_status, "msg": message, "ping": ""},
            timeout=5,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        # Don't log the exception — it can contain the full URL (token).
        log.warning("[UptimeKuma] push failed (network error).")


# --------------------------------------------------------------------------- #
# Worker: run a single monitor's check and persist results
# --------------------------------------------------------------------------- #
def resolve_tests(db, row):
    """The tests to run for this monitor: its own set if it has one,
    otherwise the global default."""
    own = parse_tests(row["tests"] if "tests" in row.keys() else None)
    if own is not None:
        return own
    return parse_tests(get_setting(db, "default_tests", ",".join(DEFAULT_TESTS))) or []


def resolve_threshold_ms(db, row):
    """The response-time threshold (ms) for this monitor: its own if set,
    otherwise the global default."""
    own = row["response_time_ms"] if "response_time_ms" in row.keys() else None
    if own is not None:
        try:
            return int(own)
        except (TypeError, ValueError):
            pass
    try:
        return int(get_setting(db, "default_response_time_ms",
                               str(DEFAULT_RESPONSE_TIME_MS)))
    except (TypeError, ValueError):
        return DEFAULT_RESPONSE_TIME_MS


def resolve_max_crl_bytes(db):
    """The maximum CRL download size (bytes): the configured `max_crl_bytes`
    setting, falling back to the MAX_CRL_BYTES default when unset or invalid."""
    try:
        n = int(get_setting(db, "max_crl_bytes", str(MAX_CRL_BYTES)))
        return n if n > 0 else MAX_CRL_BYTES
    except (TypeError, ValueError):
        return MAX_CRL_BYTES


def resolve_schedule_mode(db, row):
    """The scheduling mode for this monitor: its own if set, else the global
    default, else "frequency". Unknown values fall back to the default."""
    own = row["schedule_mode"] if "schedule_mode" in row.keys() else None
    if own in SCHEDULE_MODES:
        return own
    glob = get_setting(db, "default_schedule_mode", DEFAULT_SCHEDULE_MODE)
    return glob if glob in SCHEDULE_MODES else DEFAULT_SCHEDULE_MODE


def resolve_safety_window_min(db, row):
    """The safety window (minutes, >= 0) added after nextUpdate: the monitor's
    own if set, else the global default."""
    own = row["safety_window_min"] if "safety_window_min" in row.keys() else None
    if own is not None:
        try:
            return max(0, int(own))
        except (TypeError, ValueError):
            pass
    try:
        return max(0, int(get_setting(db, "default_safety_window_min",
                                      str(DEFAULT_SAFETY_WINDOW_MIN))))
    except (TypeError, ValueError):
        return DEFAULT_SAFETY_WINDOW_MIN


def _compute_next_run(now, mode, frequency_min, safety_window_min, next_update_iso):
    """When the next check should run.

    In "next_update" mode, schedule at the CRL's nextUpdate plus the safety
    window. Fall back to the frequency interval when nextUpdate is missing /
    unparseable, or when the computed time is already in the past (a stale CRL),
    so a stale or nextUpdate-less monitor keeps polling rather than stalling.
    """
    freq = now + timedelta(minutes=max(1, int(frequency_min or 1)))
    if mode != SCHEDULE_NEXT_UPDATE:
        return freq
    nu = _parse_ts(next_update_iso)
    if nu is None:
        return freq
    candidate = nu + timedelta(minutes=max(0, int(safety_window_min or 0)))
    return candidate if candidate > now else freq


def check_monitor(db, row):
    rid = row["id"]
    alias = row["cert_alias"]
    debug = get_setting(db, "debug_logging") == "true"
    log_only_failures = get_setting(db, "log_only_failures") == "true"
    kuma_logging = get_setting(db, "uptime_kuma_logging") == "true"

    enabled_tests = resolve_tests(db, row)
    threshold_ms = resolve_threshold_ms(db, row)
    max_bytes = resolve_max_crl_bytes(db)
    schedule_mode = resolve_schedule_mode(db, row)
    safety_window_min = resolve_safety_window_min(db, row)
    if debug:
        log.info("[Worker] checking '%s' (id=%s) uri=%s tests=%s threshold=%sms "
                 "max_bytes=%s schedule=%s safety=%smin",
                 alias, rid, row["crl_uri"], ",".join(enabled_tests) or "none",
                 threshold_ms, max_bytes, schedule_mode, safety_window_min)

    result = run_crl_check(
        row["cert_pem"], row["issuer_pem"], row["crl_uri"], enabled_tests,
        threshold_ms=threshold_ms, max_bytes=max_bytes,
    )

    now = datetime.now(timezone.utc)
    next_run = _compute_next_run(
        now, schedule_mode, row["frequency_min"], safety_window_min,
        result.next_update,
    ).isoformat()
    prev_status = row["status"]

    db.execute(
        """UPDATE monitors
              SET last_run=?, next_run=?, status=?, last_message=?,
                  response_ms=?, this_update=?, next_update=?, last_checks=?,
                  updated_at=?
            WHERE id=?""",
        (
            now.isoformat(), next_run, result.status, result.message,
            result.response_ms, result.this_update, result.next_update,
            json.dumps(result.checks), now.isoformat(), rid,
        ),
    )

    if prev_status != result.status:
        db.execute(
            "INSERT INTO history (monitor_id, status, message, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (rid, result.status, result.message, now.isoformat()),
        )
        # Trim history to HISTORY_LIMIT rows per monitor, but never drop a
        # row that carries an operator comment (it's referenced by reports).
        db.execute(
            """DELETE FROM history
                WHERE monitor_id=?
                  AND (comment IS NULL OR comment='')
                  AND id NOT IN (
                      SELECT id FROM history WHERE monitor_id=?
                      ORDER BY timestamp DESC LIMIT ?
                  )""",
            (rid, rid, HISTORY_LIMIT),
        )
        log.info("[Worker] '%s' status changed %s -> %s", alias, prev_status, result.status)

    db.commit()

    if not log_only_failures or result.status != "Valid":
        log.info("[Worker] '%s' -> %s (%s ms)", alias, result.status, result.response_ms)

    push_to_uptime_kuma(row["uptime_kuma_url"], result.status, result.message, kuma_logging)
    return result


# --------------------------------------------------------------------------- #
# Background scheduler thread
# --------------------------------------------------------------------------- #
_scheduler_started = False
_scheduler_lock = threading.Lock()


def scheduler_loop():
    log.info("[Scheduler] started; tick every %ss", SCHEDULER_INTERVAL)
    while True:
        try:
            with closing(raw_db()) as db:
                now = now_iso()
                due = db.execute(
                    "SELECT * FROM monitors WHERE enabled=1 "
                    "AND (next_run IS NULL OR next_run <= ?)",
                    (now,),
                ).fetchall()
                for row in due:
                    try:
                        check_monitor(db, row)
                    except Exception as e:  # never let one bad row kill the loop
                        log.exception("[Scheduler] check failed for id=%s: %s", row["id"], e)
        except Exception as e:
            log.exception("[Scheduler] loop error: %s", e)
        time.sleep(SCHEDULER_INTERVAL)


def start_scheduler():
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        t = threading.Thread(target=scheduler_loop, name="crl-scheduler", daemon=True)
        t.start()
        _scheduler_started = True


# --------------------------------------------------------------------------- #
# Uptime reporting engine
# --------------------------------------------------------------------------- #
# Status is recorded only on change, so each history row's status holds from its
# timestamp until the next row. Uptime is the time-weighted fraction spent in an
# "up" state over the window, with maintenance windows and (optionally) disabled
# periods excluded. All interval math is on timezone-aware UTC datetimes.
def _parse_ts(s):
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # A '+' in a query string can arrive decoded as a space (e.g.
        # "...00:00 00:00"); recover the offset rather than silently failing.
        try:
            dt = datetime.fromisoformat(s.replace(" ", "+"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _merge(intervals):
    """Merge a list of (start, end) into sorted, non-overlapping intervals."""
    ivs = sorted((s, e) for s, e in intervals if e > s)
    out = []
    for s, e in ivs:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _subtract(base, cut):
    """base minus cut (lists of (start, end))."""
    cut = _merge(cut)
    out = []
    for s, e in _merge(base):
        cur = s
        for cs, ce in cut:
            if ce <= cur or cs >= e:
                continue
            if cs > cur:
                out.append((cur, min(cs, e)))
            cur = max(cur, ce)
            if cur >= e:
                break
        if cur < e:
            out.append((cur, e))
    return out


def _intersect(a, b):
    a, b = _merge(a), _merge(b)
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        s = max(a[i][0], b[j][0])
        e = min(a[i][1], b[j][1])
        if e > s:
            out.append((s, e))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def _dur(intervals):
    return sum((e - s).total_seconds() for s, e in intervals)


def _clip_intervals(intervals, lo, hi):
    out = []
    for s, e in intervals:
        s2, e2 = max(s, lo), min(e, hi)
        if e2 > s2:
            out.append((s2, e2))
    return _merge(out)


def _disabled_intervals(db, rid, win_start, win_end):
    """Spans during which the monitor was disabled, clipped to the window."""
    events = db.execute(
        "SELECT event, timestamp FROM audit_events WHERE monitor_id=? "
        "AND event IN ('enabled','disabled') ORDER BY timestamp",
        (rid,),
    ).fetchall()
    spans, state, since = [], None, None
    for ev in events:
        t = _parse_ts(ev["timestamp"])
        if t is None:
            continue
        if ev["event"] == "disabled":
            if state != "disabled":
                since, state = t, "disabled"
        else:
            if state == "disabled" and since is not None:
                spans.append((since, t))
                since = None
            state = "enabled"
    if state == "disabled" and since is not None:
        spans.append((since, win_end))  # still disabled now
    return _clip_intervals(spans, win_start, win_end)


def _maintenance_intervals(db, rid, win_start, win_end):
    rows = db.execute(
        "SELECT start_ts, end_ts FROM maintenance_windows "
        "WHERE monitor_id=? OR monitor_id IS NULL",
        (rid,),
    ).fetchall()
    spans = []
    for r in rows:
        s, e = _parse_ts(r["start_ts"]), _parse_ts(r["end_ts"])
        if s and e:
            spans.append((s, e))
    return _clip_intervals(spans, win_start, win_end)


def _status_segments(db, rid, win_start, win_end):
    """List of (start, end, row) over the window; row is None for no-data gaps."""
    rows = db.execute(
        "SELECT id, status, message, timestamp, comment FROM history "
        "WHERE monitor_id=? ORDER BY timestamp",
        (rid,),
    ).fetchall()
    seed, mids = None, []
    for r in rows:
        t = _parse_ts(r["timestamp"])
        if t is None:
            continue
        if t <= win_start:
            seed = r
        elif t < win_end:
            mids.append((t, r))
    segs, cursor, cur = [], win_start, seed
    for t, r in mids:
        segs.append((cursor, t, cur))
        cursor, cur = t, r
    segs.append((cursor, win_end, cur))
    return segs


def _is_up(status, down_mode):
    if status is None:
        return None
    if status == "Valid":
        return True
    if down_mode == "error_only":
        return status != "Error"   # Revoked / Unknown count as "up" (answered)
    return False                   # not_valid: anything other than Valid is down


def compute_uptime(db, rid, win_start, win_end, down_mode="not_valid",
                   exclude_maintenance=True, disabled_mode="exclude"):
    """Time-weighted uptime over [win_start, win_end] for one monitor."""
    up, down, nodata, downtimes = [], [], [], []
    for s, e, row in _status_segments(db, rid, win_start, win_end):
        if row is None:
            nodata.append((s, e))
            continue
        if _is_up(row["status"], down_mode):
            up.append((s, e))
        else:
            down.append((s, e))
            downtimes.append({
                "hist_id": row["id"], "status": row["status"],
                "reason": row["message"], "comment": row["comment"],
                "_start": s, "_end": e,
            })

    maint = _maintenance_intervals(db, rid, win_start, win_end) if exclude_maintenance else []
    disabled = _disabled_intervals(db, rid, win_start, win_end)

    disabled_excluded = []
    if disabled_mode == "exclude":
        disabled_excluded = disabled
        up, down = _subtract(up, disabled), _subtract(down, disabled)
    elif disabled_mode == "down":
        moved = _intersect(up, disabled)      # "up" time while disabled -> down
        up = _subtract(up, disabled)
        down = _merge(down + moved)
    # "ignore": leave classification untouched

    if maint:
        up, down = _subtract(up, maint), _subtract(down, maint)
        disabled_excluded = _subtract(disabled_excluded, maint)
        nodata = _subtract(nodata, maint)

    up_s, down_s = _dur(up), _dur(down)
    denom = up_s + down_s
    uptime_pct = round(100.0 * up_s / denom, 4) if denom > 0 else None

    # Flag downtimes fully inside excluded (maintenance / disabled) time.
    flag_excl = _merge(maint + (disabled if disabled_mode == "exclude" else []))
    for d in downtimes:
        visible = _subtract([(d["_start"], d["_end"])], flag_excl)
        d["excluded"] = _dur(visible) == 0
        d["duration_s"] = (d["_end"] - d["_start"]).total_seconds()
        d["start"], d["end"] = d.pop("_start").isoformat(), d.pop("_end").isoformat()

    return {
        "uptime_pct": uptime_pct,
        "up_seconds": up_s,
        "down_seconds": down_s,
        "maintenance_seconds": _dur(maint),
        "disabled_seconds": _dur(disabled_excluded) if disabled_mode == "exclude" else 0.0,
        "nodata_seconds": _dur(nodata),
        "downtimes": downtimes,
    }


# --------------------------------------------------------------------------- #
# Flask app
# --------------------------------------------------------------------------- #
app = Flask(__name__)
# Trust X-Forwarded-* only for the configured number of proxy hops. Setting
# TRUSTED_PROXY_HOPS=0 disables ProxyFix, which is the correct choice when the
# app is exposed directly (otherwise clients can spoof X-Forwarded-* to forge
# source IPs and influence generated URLs). Match the count to your topology.
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS,
        x_host=TRUSTED_PROXY_HOPS, x_prefix=TRUSTED_PROXY_HOPS,
    )


# --------------------------------------------------------------------------- #
# Lightweight per-IP token-bucket rate limiting (single-process, in-memory)
# --------------------------------------------------------------------------- #
_rl_lock = threading.Lock()
_rl_buckets = {}  # (ip, name) -> [tokens, last_refill_monotonic]


def _rate_ok(name, capacity):
    """Token bucket: `capacity` requests per 60s per client IP. 0 = unlimited."""
    if capacity <= 0:
        return True
    ip = request.remote_addr or "unknown"
    now = time.monotonic()
    rate = capacity / 60.0
    with _rl_lock:
        tokens, last = _rl_buckets.get((ip, name), (capacity, now))
        tokens = min(capacity, tokens + (now - last) * rate)
        if tokens < 1:
            _rl_buckets[(ip, name)] = (tokens, now)
            return False
        _rl_buckets[(ip, name)] = (tokens - 1, now)
        return True


@app.before_request
def _guard_requests():
    """CSRF + rate-limit guard for state-changing API requests.

    Cross-site form posts can't set a custom header without triggering a CORS
    preflight (which we don't answer), so requiring X-Requested-With blocks
    forged requests from other origins. We also require a JSON content type for
    requests with a body and apply per-IP rate limits.
    """
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return None
    if not request.path.startswith("/api/"):
        return None

    if not request.headers.get("X-Requested-With"):
        return jsonify({"message": "Missing X-Requested-With header."}), 403

    if request.method in ("POST", "PUT", "PATCH") and request.get_data():
        ctype = (request.content_type or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return jsonify({"message": "Content-Type must be application/json."}), 415

    limit = RATE_LIMIT_CHECK if request.path.endswith("/check") else RATE_LIMIT_MUTATE
    bucket = "check" if request.path.endswith("/check") else "mutate"
    if not _rate_ok(bucket, limit):
        return jsonify({"message": "Rate limit exceeded. Slow down."}), 429
    return None


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def _mask_secret_url(url):
    """Mask the token-bearing path/query of a push URL, keeping scheme+host."""
    if not url:
        return ""
    try:
        p = urlsplit(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}/…/••••"
    except ValueError:
        pass
    return "••••"


def _load_checks(value):
    """Decode the stored last_checks JSON into a list (empty on error/None)."""
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def monitor_to_dict(row, include_pem=True):
    d = {
        "id": row["id"],
        "cert_alias": row["cert_alias"],
        "crl_uri": row["crl_uri"],
        "frequency_min": row["frequency_min"],
        "enabled": bool(row["enabled"]),
        # The push URL embeds a secret token. The single-monitor detail view
        # (include_pem=True), used by the edit/clone form, returns it verbatim
        # so the operator can verify and clone it; the bulk list stays masked to
        # avoid spraying every token across one response.
        "uptime_kuma_url": (row["uptime_kuma_url"] if include_pem
                            else _mask_secret_url(row["uptime_kuma_url"])),
        "uptime_kuma_url_set": bool((row["uptime_kuma_url"] or "").strip()),
        # None means "inherit the global default set".
        "tests": parse_tests(row["tests"] if "tests" in row.keys() else None),
        # None means "inherit the global default threshold".
        "response_time_ms": (row["response_time_ms"]
                             if "response_time_ms" in row.keys() else None),
        # None on either means "inherit the global scheduling default".
        "schedule_mode": (row["schedule_mode"]
                          if "schedule_mode" in row.keys() else None),
        "safety_window_min": (row["safety_window_min"]
                              if "safety_window_min" in row.keys() else None),
        "last_checks": _load_checks(row["last_checks"] if "last_checks" in row.keys() else None),
        "last_run": row["last_run"],
        "next_run": row["next_run"],
        "status": row["status"],
        "last_message": row["last_message"],
        "response_ms": row["response_ms"],
        "this_update": row["this_update"],
        "next_update": row["next_update"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_pem:
        d["cert_pem"] = row["cert_pem"]
        d["issuer_pem"] = row["issuer_pem"]
    return d


# ---- UI ---- #
@app.route("/")
def index():
    # The single-page shell carries the JS that talks to the API, so never let
    # a browser serve a stale copy against a newer backend (e.g. a cached page
    # that predates the X-Requested-With requirement).
    resp = app.make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


# ---- Health ---- #
@app.route("/api/status")
def api_status():
    try:
        get_db().execute("SELECT 1")
        return jsonify({"status": "ok", "database": "connected"})
    except Exception as e:
        log.error("[Health] database check failed: %s", e)
        return jsonify({"status": "error", "database": "unavailable"}), 500


# ---- Monitors CRUD ---- #
@app.route("/api/monitors", methods=["GET"])
def list_monitors():
    db = get_db()
    rows = db.execute("SELECT * FROM monitors ORDER BY cert_alias").fetchall()
    return jsonify([monitor_to_dict(r, include_pem=False) for r in rows])


@app.route("/api/monitors/<int:rid>", methods=["GET"])
def get_monitor(rid):
    db = get_db()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404
    return jsonify(monitor_to_dict(row, include_pem=True))


def _tests_to_db(value):
    """Normalize an incoming `tests` value to what we store.

    None -> NULL (inherit the global default). A list -> a JSON array of clean
    known keys (an explicit empty list is preserved as "run no tests").
    """
    if value is None:
        return None
    cleaned = parse_tests(value)
    return None if cleaned is None else json.dumps(cleaned)


def _int_or_none(value):
    """Parse an optional integer; blank/None/garbage -> None (inherit)."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _schedule_mode_or_none(value):
    """Normalize an incoming schedule_mode; blank/None/unknown -> None (inherit)."""
    if value is None or value == "":
        return None
    return value if value in SCHEDULE_MODES else None


def _safety_window_or_none(value):
    """Parse an optional safety window (minutes, clamped >= 0); blank -> None."""
    n = _int_or_none(value)
    return None if n is None else max(0, n)


def _validate_payload(data, partial=False):
    errors = []
    if not partial or "cert_alias" in data:
        if not (data.get("cert_alias") or "").strip():
            errors.append("cert_alias is required.")
    for field in ("cert_pem", "issuer_pem"):
        if partial and field not in data:
            continue
        value = data.get(field) or ""
        if "BEGIN CERTIFICATE" not in value:
            errors.append(f"{field} must be a PEM certificate.")
        elif len(value.encode("utf-8")) > MAX_PEM_BYTES:
            errors.append(f"{field} exceeds the maximum size of {MAX_PEM_BYTES} bytes.")
    return errors


@app.route("/api/monitors", methods=["POST"])
def create_monitor():
    data = request.get_json(silent=True) or {}
    errors = _validate_payload(data)
    if errors:
        return jsonify({"message": "Validation failed", "errors": errors}), 400
    db = get_db()
    if MAX_MONITORS > 0:
        count = db.execute("SELECT COUNT(*) AS n FROM monitors").fetchone()["n"]
        if count >= MAX_MONITORS:
            return jsonify({"message": f"Monitor limit ({MAX_MONITORS}) reached."}), 409
    now = now_iso()
    cur = db.execute(
        """INSERT INTO monitors
           (cert_alias, cert_pem, issuer_pem, crl_uri, frequency_min,
            enabled, uptime_kuma_url, tests, response_time_ms,
            schedule_mode, safety_window_min, next_run, status,
            last_message, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data["cert_alias"].strip(),
            data["cert_pem"].strip(),
            data["issuer_pem"].strip(),
            (data.get("crl_uri") or "").strip(),
            int(data.get("frequency_min", 60)),
            1 if data.get("enabled", True) else 0,
            (data.get("uptime_kuma_url") or "").strip(),
            _tests_to_db(data.get("tests")),
            _int_or_none(data.get("response_time_ms")),
            _schedule_mode_or_none(data.get("schedule_mode")),
            _safety_window_or_none(data.get("safety_window_min")),
            now,  # schedule an immediate first run
            "Unknown",
            "Configuration created.",
            now,
            now,
        ),
    )
    # Seed the audit log so disabled-period math has a clean starting point.
    add_audit(db, cur.lastrowid, "created")
    add_audit(db, cur.lastrowid, "enabled" if data.get("enabled", True) else "disabled")
    db.commit()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(monitor_to_dict(row)), 201


@app.route("/api/monitors/<int:rid>", methods=["PUT"])
def update_monitor(rid):
    data = request.get_json(silent=True) or {}
    errors = _validate_payload(data, partial=True)
    if errors:
        return jsonify({"message": "Validation failed", "errors": errors}), 400
    db = get_db()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404

    fields = {
        "cert_alias": (data.get("cert_alias") or row["cert_alias"]).strip(),
        "cert_pem": (data.get("cert_pem") or row["cert_pem"]).strip(),
        "issuer_pem": (data.get("issuer_pem") or row["issuer_pem"]).strip(),
        "crl_uri": (data.get("crl_uri", row["crl_uri"]) or "").strip(),
        "frequency_min": int(data.get("frequency_min", row["frequency_min"])),
        "enabled": 1 if data.get("enabled", bool(row["enabled"])) else 0,
        # The detail view returns the real push URL, so the form field is
        # authoritative: save exactly what it holds (empty clears it). Only an
        # omitted key leaves the stored value untouched.
        "uptime_kuma_url": (
            (data.get("uptime_kuma_url") or "").strip()
            if "uptime_kuma_url" in data else row["uptime_kuma_url"]
        ),
        # Only touch the test selection if the client sent it.
        "tests": _tests_to_db(data["tests"]) if "tests" in data else row["tests"],
        "response_time_ms": (_int_or_none(data["response_time_ms"])
                             if "response_time_ms" in data else row["response_time_ms"]),
        "schedule_mode": (_schedule_mode_or_none(data["schedule_mode"])
                          if "schedule_mode" in data else row["schedule_mode"]),
        "safety_window_min": (_safety_window_or_none(data["safety_window_min"])
                              if "safety_window_min" in data else row["safety_window_min"]),
    }
    # Re-check immediately if cert material changed.
    next_run = row["next_run"]
    if fields["cert_pem"] != row["cert_pem"] or fields["issuer_pem"] != row["issuer_pem"]:
        next_run = now_iso()

    db.execute(
        """UPDATE monitors SET cert_alias=?, cert_pem=?, issuer_pem=?, crl_uri=?,
               frequency_min=?, enabled=?, uptime_kuma_url=?, tests=?,
               response_time_ms=?, schedule_mode=?, safety_window_min=?,
               next_run=?, updated_at=?
           WHERE id=?""",
        (
            fields["cert_alias"], fields["cert_pem"], fields["issuer_pem"],
            fields["crl_uri"], fields["frequency_min"], fields["enabled"],
            fields["uptime_kuma_url"], fields["tests"], fields["response_time_ms"],
            fields["schedule_mode"], fields["safety_window_min"],
            next_run, now_iso(), rid,
        ),
    )
    # Audit an enable/disable that happened via the edit form.
    if fields["enabled"] != int(bool(row["enabled"])):
        add_audit(db, rid, "enabled" if fields["enabled"] else "disabled")
    db.commit()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    return jsonify(monitor_to_dict(row))


def _set_enabled(rid, enabled):
    """Shared enable/disable: update the flag, audit it, reschedule if enabling."""
    db = get_db()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404
    if bool(row["enabled"]) == enabled:
        return jsonify(monitor_to_dict(row, include_pem=False))  # no-op
    # Enabling schedules an immediate check; disabling leaves next_run as-is.
    next_run = now_iso() if enabled else row["next_run"]
    db.execute(
        "UPDATE monitors SET enabled=?, next_run=?, updated_at=? WHERE id=?",
        (1 if enabled else 0, next_run, now_iso(), rid),
    )
    add_audit(db, rid, "enabled" if enabled else "disabled")
    db.commit()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    return jsonify(monitor_to_dict(row, include_pem=False))


@app.route("/api/monitors/<int:rid>/enable", methods=["POST"])
def enable_monitor(rid):
    return _set_enabled(rid, True)


@app.route("/api/monitors/<int:rid>/disable", methods=["POST"])
def disable_monitor(rid):
    return _set_enabled(rid, False)


@app.route("/api/monitors/<int:rid>/audit", methods=["GET"])
def monitor_audit(rid):
    db = get_db()
    rows = db.execute(
        "SELECT event, timestamp FROM audit_events WHERE monitor_id=? "
        "ORDER BY timestamp DESC LIMIT 200",
        (rid,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/monitors/<int:rid>", methods=["DELETE"])
def delete_monitor(rid):
    db = get_db()
    cur = db.execute("DELETE FROM monitors WHERE id=?", (rid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"message": "Not found"}), 404
    return ("", 204)


@app.route("/api/monitors/<int:rid>/check", methods=["POST"])
def check_now(rid):
    """Run a check immediately and return the result."""
    db = get_db()
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404
    check_monitor(db, row)
    row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
    return jsonify(monitor_to_dict(row, include_pem=False))


@app.route("/api/monitors/<int:rid>/history", methods=["GET"])
def monitor_history(rid):
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), HISTORY_LIMIT)
    rows = db.execute(
        "SELECT id, status, message, timestamp, comment FROM history "
        "WHERE monitor_id=? ORDER BY timestamp DESC LIMIT ?",
        (rid, limit),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---- Downtime comments ---- #
@app.route("/api/history/<int:hid>", methods=["PUT"])
def update_history_comment(hid):
    """Attach (or clear) an operator comment on a status-change row."""
    data = request.get_json(silent=True) or {}
    comment = (data.get("comment") or "").strip()
    db = get_db()
    cur = db.execute("UPDATE history SET comment=? WHERE id=?", (comment or None, hid))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"message": "Not found"}), 404
    row = db.execute(
        "SELECT id, status, message, timestamp, comment FROM history WHERE id=?", (hid,)
    ).fetchone()
    return jsonify(dict(row))


# ---- Maintenance windows ---- #
@app.route("/api/maintenance", methods=["GET"])
def list_maintenance():
    db = get_db()
    rid = request.args.get("monitor_id")
    if rid and rid.isdigit():
        rows = db.execute(
            "SELECT * FROM maintenance_windows WHERE monitor_id=? OR monitor_id IS NULL "
            "ORDER BY start_ts DESC", (int(rid),),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM maintenance_windows ORDER BY start_ts DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/maintenance", methods=["POST"])
def create_maintenance():
    data = request.get_json(silent=True) or {}
    s, e = _parse_ts(data.get("start")), _parse_ts(data.get("end"))
    if not s or not e or e <= s:
        return jsonify({"message": "Valid 'start' and 'end' (end after start) are required."}), 400
    db = get_db()
    rid = data.get("monitor_id")
    rid = int(rid) if (rid not in (None, "") and str(rid).isdigit()) else None
    if rid is not None and not db.execute(
            "SELECT 1 FROM monitors WHERE id=?", (rid,)).fetchone():
        return jsonify({"message": "Unknown monitor_id."}), 400
    cur = db.execute(
        "INSERT INTO maintenance_windows (monitor_id, start_ts, end_ts, comment, created_at) "
        "VALUES (?,?,?,?,?)",
        (rid, s.isoformat(), e.isoformat(), (data.get("comment") or "").strip(), now_iso()),
    )
    db.commit()
    row = db.execute("SELECT * FROM maintenance_windows WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(dict(row)), 201


@app.route("/api/maintenance/<int:mid>", methods=["DELETE"])
def delete_maintenance(mid):
    db = get_db()
    cur = db.execute("DELETE FROM maintenance_windows WHERE id=?", (mid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"message": "Not found"}), 404
    return ("", 204)


# ---- Reports ---- #
def _report_params():
    args = request.args
    win_end = _parse_ts(args.get("to")) or datetime.now(timezone.utc)
    win_start = _parse_ts(args.get("from")) or (win_end - timedelta(days=30))
    ids = (args.get("monitor_ids") or "").strip()
    rid_list = [int(x) for x in ids.split(",") if x.strip().isdigit()] if ids else None
    down_mode = args.get("down_mode", "not_valid")
    if down_mode not in ("not_valid", "error_only"):
        down_mode = "not_valid"
    exclude_maint = (args.get("exclude_maintenance", "true").lower() != "false")
    disabled_mode = args.get("disabled_mode", "exclude")
    if disabled_mode not in ("exclude", "down", "ignore"):
        disabled_mode = "exclude"
    return win_start, win_end, rid_list, down_mode, exclude_maint, disabled_mode


def _selected_monitors(db, rid_list):
    rows = db.execute("SELECT id, cert_alias FROM monitors ORDER BY cert_alias").fetchall()
    return [r for r in rows if rid_list is None or r["id"] in rid_list]


@app.route("/api/reports/uptime", methods=["GET"])
def report_uptime():
    db = get_db()
    ws, we, ids, dm, em, dim = _report_params()
    if we <= ws:
        return jsonify({"message": "'to' must be after 'from'."}), 400
    out = []
    for r in _selected_monitors(db, ids):
        rep = compute_uptime(db, r["id"], ws, we, dm, em, dim)
        rep["monitor_id"], rep["cert_alias"] = r["id"], r["cert_alias"]
        out.append(rep)
    return jsonify({
        "from": ws.isoformat(), "to": we.isoformat(), "down_mode": dm,
        "exclude_maintenance": em, "disabled_mode": dim, "monitors": out,
    })


@app.route("/api/reports/downtimes", methods=["GET"])
def report_downtimes():
    db = get_db()
    ws, we, ids, dm, em, dim = _report_params()
    if we <= ws:
        return jsonify({"message": "'to' must be after 'from'."}), 400
    items = []
    for r in _selected_monitors(db, ids):
        rep = compute_uptime(db, r["id"], ws, we, dm, em, dim)
        for d in rep["downtimes"]:
            items.append({**d, "monitor_id": r["id"], "cert_alias": r["cert_alias"]})
    items.sort(key=lambda d: d["start"])
    return jsonify({"from": ws.isoformat(), "to": we.isoformat(), "downtimes": items})


# ---- Tests registry ---- #
@app.route("/api/tests", methods=["GET"])
def list_tests():
    """The catalogue of selectable verification tests (key, label, group)."""
    return jsonify([{"key": k, "label": v, "group": test_group(k)}
                    for k, v in TESTS])


# ---- Settings ---- #
@app.route("/api/settings", methods=["GET"])
def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    out = {}
    for r in rows:
        v = r["value"]
        if r["key"] == "default_tests":
            out[r["key"]] = parse_tests(v) or []
        else:
            out[r["key"]] = (v == "true") if v in ("true", "false") else v
    return jsonify(out)


@app.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(silent=True) or {}
    db = get_db()
    # Only known settings keys may be written (no arbitrary key injection).
    for k, v in data.items():
        if k not in DEFAULT_SETTINGS:
            continue
        if k == "default_tests":
            sv = ",".join(parse_tests(v) or [])
        elif k == "default_response_time_ms":
            sv = str(_int_or_none(v) or DEFAULT_RESPONSE_TIME_MS)
        elif k == "max_crl_bytes":
            n = _int_or_none(v)
            sv = str(n if (n and n > 0) else MAX_CRL_BYTES)
        elif k == "default_schedule_mode":
            sv = v if v in SCHEDULE_MODES else DEFAULT_SCHEDULE_MODE
        elif k == "default_safety_window_min":
            n = _int_or_none(v)
            sv = str(max(0, n) if n is not None else DEFAULT_SAFETY_WINDOW_MIN)
        elif v is True:
            sv = "true"
        elif v is False:
            sv = "false"
        else:
            sv = str(v)
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (k, sv),
        )
    db.commit()
    return get_settings()


# Initialise DB + scheduler at import time (works under gunicorn too).
init_db()
start_scheduler()

# Apply URL prefix for subpath deployments.
if URL_PREFIX:
    def _not_found(environ, start_response):
        res = Response(
            f"Not found. App is mounted at '{URL_PREFIX}'.",
            status=404, mimetype="text/plain",
        )
        return res(environ, start_response)

    app.wsgi_app = DispatcherMiddleware(_not_found, {URL_PREFIX: app.wsgi_app})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
