"""Functional tests for the CRL check engine.

These build a throwaway CA, an end-entity certificate, and a signed CRL in
memory with the `cryptography` library, then drive `run_crl_check` with the
network download stubbed out. They assert the core behaviours: a not-revoked
cert is Valid, a revoked cert is Revoked, a bad signature / stale CRL / wrong
issuer fail, and an unreachable endpoint is an Error.
"""
import os
import importlib.util
from datetime import datetime, timezone, timedelta

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "app.py")


@pytest.fixture(scope="module")
def m(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(d)
    os.environ["DB_PATH"] = str(d / "crl_test.db")
    os.environ["TRUSTED_PROXY_HOPS"] = "0"
    spec = importlib.util.spec_from_file_location("crl_engine_under_test", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Tiny PKI built on the fly
# --------------------------------------------------------------------------- #
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(cn="Test CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, cn="leaf", serial=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return cert


def _make_crl(ca_key, ca_cert, revoked_serials=(),
              last_days=-1, next_days=7):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now + timedelta(days=last_days))
        .next_update(now + timedelta(days=next_days))
    )
    for s in revoked_serials:
        rc = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(now - timedelta(days=1))
            .build()
        )
        builder = builder.add_revoked_certificate(rc)
    return builder.sign(ca_key, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _stub_download(m, monkeypatch, crl, status=200, too_large=False, raise_exc=None):
    der = crl.public_bytes(serialization.Encoding.DER) if crl is not None else b""

    def fake(url, timeout, max_bytes):
        if raise_exc is not None:
            raise raise_exc
        return status, der, too_large

    monkeypatch.setattr(m, "_download_crl", fake)


DEFAULTS = ["cert_load", "crl_url", "reachable", "http_200", "crl_parse",
            "cert_status", "crl_signature", "issuer_match", "this_update", "next_update"]


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_good_cert_is_valid(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, revoked_serials=[])
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Valid", res.message
    assert all(c["status"] == "pass" for c in res.checks), res.checks


def test_revoked_cert_is_revoked(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca, serial=12345)
    crl = _make_crl(ca_key, ca, revoked_serials=[12345])
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Revoked", res.message
    cert_status = next(c for c in res.checks if c["key"] == "cert_status")
    assert cert_status["status"] == "fail"


def test_wrong_issuer_signature_fails(m, monkeypatch):
    ca_key, ca = _make_ca("Real CA")
    other_key, other_ca = _make_ca("Other CA")
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, revoked_serials=[])
    _stub_download(m, monkeypatch, crl)

    # Verify the CRL (signed by Real CA) against the wrong issuer cert.
    res = m.run_crl_check(_pem(leaf), _pem(other_ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Error"
    sig = next(c for c in res.checks if c["key"] == "crl_signature")
    assert sig["status"] == "fail"


def test_stale_crl_fails_next_update(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    # nextUpdate already in the past.
    crl = _make_crl(ca_key, ca, revoked_serials=[], last_days=-10, next_days=-2)
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Error"
    nu = next(c for c in res.checks if c["key"] == "next_update")
    assert nu["status"] == "fail"


def test_unreachable_endpoint_is_error(m, monkeypatch):
    import requests
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    _stub_download(m, monkeypatch, None,
                   raise_exc=requests.exceptions.ConnectionError("boom"))

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Error"
    reach = next(c for c in res.checks if c["key"] == "reachable")
    assert reach["status"] == "fail"


def test_no_crl_url_available(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)  # no CRLDistributionPoints extension
    # No override URL and no CDP in the cert -> crl_url step fails.
    res = m.run_crl_check(_pem(leaf), _pem(ca), "", DEFAULTS)
    assert res.status == "Error"
    url = next(c for c in res.checks if c["key"] == "crl_url")
    assert url["status"] == "fail"


def test_too_large_crl_reports_configured_limit(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, revoked_serials=[])
    _stub_download(m, monkeypatch, crl, too_large=True)

    # The configured max_bytes flows through to the failure message.
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS, max_bytes=12345)
    assert res.status == "Error"
    parse = next(c for c in res.checks if c["key"] == "crl_parse")
    assert parse["status"] == "fail"
    assert "12345" in parse["message"]


def test_compute_next_run_frequency_mode(m):
    now = datetime.now(timezone.utc)
    nu = (now + timedelta(days=5)).isoformat()
    nr = m._compute_next_run(now, "frequency", 60, 30, nu)
    assert abs((nr - (now + timedelta(minutes=60))).total_seconds()) < 1


def test_compute_next_run_next_update_adds_safety(m):
    now = datetime.now(timezone.utc)
    nu = now + timedelta(days=2)
    nr = m._compute_next_run(now, "next_update", 60, 90, nu.isoformat())
    assert abs((nr - (nu + timedelta(minutes=90))).total_seconds()) < 1


def test_compute_next_run_falls_back_when_stale(m):
    now = datetime.now(timezone.utc)
    nu = (now - timedelta(days=1)).isoformat()  # nextUpdate already in the past
    nr = m._compute_next_run(now, "next_update", 45, 60, nu)
    assert abs((nr - (now + timedelta(minutes=45))).total_seconds()) < 1


def test_compute_next_run_falls_back_when_no_next_update(m):
    now = datetime.now(timezone.utc)
    nr = m._compute_next_run(now, "next_update", 45, 60, None)
    assert abs((nr - (now + timedelta(minutes=45))).total_seconds()) < 1


def test_deselecting_cert_status_keeps_revoked_off_status(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca, serial=999)
    crl = _make_crl(ca_key, ca, revoked_serials=[999])
    _stub_download(m, monkeypatch, crl)

    tests = [t for t in DEFAULTS if t != "cert_status"]
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", tests)
    # Revocation is no longer evaluated, so the monitor is Valid.
    assert res.status == "Valid", res.message
