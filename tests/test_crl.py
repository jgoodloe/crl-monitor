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
              last_days=-1, next_days=7, crl_number=None, idp=None, sig_hash=None,
              revoked_reason=None, freshest=None, delta_indicator=None):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now + timedelta(days=last_days))
        .next_update(now + timedelta(days=next_days))
    )
    if crl_number is not None:
        builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)
    if idp is not None:
        builder = builder.add_extension(idp, critical=False)
    if freshest is not None:
        builder = builder.add_extension(
            x509.FreshestCRL([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(freshest)],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    if delta_indicator is not None:
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(delta_indicator), critical=True)
    for s in revoked_serials:
        rc = (x509.RevokedCertificateBuilder()
              .serial_number(s)
              .revocation_date(now - timedelta(days=1)))
        if revoked_reason is not None:
            rc = rc.add_extension(x509.CRLReason(revoked_reason), critical=False)
        builder = builder.add_revoked_certificate(rc.build())
    return builder.sign(ca_key, sig_hash or hashes.SHA256())


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


CRL_NUM_TESTS = DEFAULTS + ["crl_number"]


def test_crl_number_present_passes(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, crl_number=7)
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", CRL_NUM_TESTS)
    assert res.status == "Valid", res.message
    assert res.crl_number == 7
    cn = next(c for c in res.checks if c["key"] == "crl_number")
    assert cn["status"] == "pass"


def test_crl_number_absent_fails(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca)  # no CRL Number extension
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", CRL_NUM_TESTS)
    assert res.status == "Error"
    assert res.crl_number is None
    cn = next(c for c in res.checks if c["key"] == "crl_number")
    assert cn["status"] == "fail"


def test_crl_number_regression_fails(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, crl_number=5)
    _stub_download(m, monkeypatch, crl)

    # A lower number than last seen (10) is a rollback -> fail.
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          CRL_NUM_TESTS, prev_crl_number=10)
    assert res.status == "Error"
    cn = next(c for c in res.checks if c["key"] == "crl_number")
    assert cn["status"] == "fail"


def test_crl_number_monotonic_increase_passes(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, crl_number=11)
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          CRL_NUM_TESTS, prev_crl_number=5)
    assert res.status == "Valid", res.message
    cn = next(c for c in res.checks if c["key"] == "crl_number")
    assert cn["status"] == "pass"


def test_check_monitor_persists_crl_number_and_detects_rollback(m, monkeypatch):
    """End-to-end through the worker: the CRL Number is persisted, then a later
    lower number is flagged as a rollback (Error)."""
    from contextlib import closing
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    with closing(m.raw_db()) as db:
        ts = m.now_iso()
        cur = db.execute(
            "INSERT INTO monitors (cert_alias, cert_pem, issuer_pem, crl_uri, "
            "tests, frequency_min, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ("rollback", _pem(leaf), _pem(ca), "http://crl.test/ca.crl",
             ",".join(CRL_NUM_TESTS), 60, ts, ts),
        )
        rid = cur.lastrowid
        db.commit()

        crl1 = _make_crl(ca_key, ca, crl_number=10)
        _stub_download(m, monkeypatch, crl1)
        row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
        res1 = m.check_monitor(db, row)
        assert res1.status == "Valid", res1.message
        assert db.execute("SELECT last_crl_number FROM monitors WHERE id=?",
                          (rid,)).fetchone()["last_crl_number"] == "10"

        crl2 = _make_crl(ca_key, ca, crl_number=4)  # rolled back
        _stub_download(m, monkeypatch, crl2)
        row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
        res2 = m.check_monitor(db, row)
        assert res2.status == "Error", res2.message
        cn = next(c for c in res2.checks if c["key"] == "crl_number")
        assert cn["status"] == "fail"


class _FakeCRL:
    """Minimal stand-in for evaluating the weak-signature rule; cryptography 44
    refuses to *sign* a CRL with SHA-1, so we can't build one to download."""
    def __init__(self, hash_alg):
        self.signature_hash_algorithm = hash_alg

    def get_revoked_certificate_by_serial_number(self, serial):
        return None


def test_weak_signature_sha1_fails(m):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    fake = _FakeCRL(hashes.SHA1())
    checks, _ = m._evaluate_tests(["weak_signature"], fake, None, None, ca, leaf)
    ws = next(c for c in checks if c["key"] == "weak_signature")
    assert ws["status"] == "fail"
    assert m._signature_hash_name(fake) == "sha1"
    assert "sha1" in m.WEAK_SIGNATURE_HASHES


def test_weak_signature_sha256_passes(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca)  # signed with SHA-256 by default
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["weak_signature"])
    assert res.status == "Valid", res.message
    ws = next(c for c in res.checks if c["key"] == "weak_signature")
    assert ws["status"] == "pass"


def _idp(**kw):
    base = dict(full_name=None, relative_name=None, only_contains_user_certs=False,
                only_contains_ca_certs=False, only_some_reasons=None,
                indirect_crl=False, only_contains_attribute_certs=False)
    base.update(kw)
    return x509.IssuingDistributionPoint(**base)


def test_idp_absent_passes(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca)  # no IDP extension
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["idp"])
    assert res.status == "Valid", res.message
    idp = next(c for c in res.checks if c["key"] == "idp")
    assert idp["status"] == "pass"


def test_idp_ca_scope_mismatch_fails(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)  # end-entity (no BasicConstraints cA)
    crl = _make_crl(ca_key, ca, idp=_idp(only_contains_ca_certs=True))
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["idp"])
    assert res.status == "Error"
    idp = next(c for c in res.checks if c["key"] == "idp")
    assert idp["status"] == "fail"


def test_idp_dp_name_match_passes_mismatch_fails(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)

    matching = _idp(full_name=[x509.UniformResourceIdentifier("http://crl.test/ca.crl")])
    crl = _make_crl(ca_key, ca, idp=matching)
    _stub_download(m, monkeypatch, crl)
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["idp"])
    assert res.status == "Valid", res.message

    mismatch = _idp(full_name=[x509.UniformResourceIdentifier("http://other.test/x.crl")])
    crl = _make_crl(ca_key, ca, idp=mismatch)
    _stub_download(m, monkeypatch, crl)
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["idp"])
    assert res.status == "Error"
    idp = next(c for c in res.checks if c["key"] == "idp")
    assert idp["status"] == "fail"


def test_revocation_reason_surfaced(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca, serial=4242)
    crl = _make_crl(ca_key, ca, revoked_serials=[4242],
                    revoked_reason=x509.ReasonFlags.key_compromise)
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.status == "Revoked", res.message
    cs = next(c for c in res.checks if c["key"] == "cert_status")
    assert "keyCompromise" in cs["message"]


def test_retry_compute_fixed_and_backoff(m):
    now = datetime.now(timezone.utc)
    fixed = m._compute_retry_run(now, 3, 5, False, 120)
    assert abs((fixed - (now + timedelta(minutes=5))).total_seconds()) < 1
    # backoff: 5 * 2^(3-1) = 20
    bo = m._compute_retry_run(now, 3, 5, True, 120)
    assert abs((bo - (now + timedelta(minutes=20))).total_seconds()) < 1
    # backoff capped at retry_max_min
    capped = m._compute_retry_run(now, 10, 5, True, 30)
    assert abs((capped - (now + timedelta(minutes=30))).total_seconds()) < 1


def test_check_monitor_retry_on_failure_then_reset(m, monkeypatch):
    import requests
    from contextlib import closing
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    with closing(m.raw_db()) as db:
        ts = m.now_iso()
        cur = db.execute(
            "INSERT INTO monitors (cert_alias, cert_pem, issuer_pem, crl_uri, tests, "
            "frequency_min, retry_min, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("retry", _pem(leaf), _pem(ca), "http://crl.test/ca.crl",
             ",".join(DEFAULTS), 600, 7, ts, ts),
        )
        rid = cur.lastrowid
        db.commit()

        _stub_download(m, monkeypatch, None,
                       raise_exc=requests.exceptions.ConnectionError("x"))
        row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
        assert m.check_monitor(db, row).status == "Error"
        r = db.execute("SELECT consecutive_failures, next_run, last_run "
                       "FROM monitors WHERE id=?", (rid,)).fetchone()
        assert r["consecutive_failures"] == 1
        gap = (m._parse_ts(r["next_run"]) - m._parse_ts(r["last_run"])).total_seconds() / 60
        assert 6 <= gap <= 8  # the 7-min retry, not the 600-min frequency

        _stub_download(m, monkeypatch, _make_crl(ca_key, ca))
        row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
        assert m.check_monitor(db, row).status == "Valid"
        r = db.execute("SELECT consecutive_failures, next_run, last_run "
                       "FROM monitors WHERE id=?", (rid,)).fetchone()
        assert r["consecutive_failures"] == 0
        gap = (m._parse_ts(r["next_run"]) - m._parse_ts(r["last_run"])).total_seconds() / 60
        assert gap > 100  # back to the frequency schedule


def test_check_monitor_records_crl_snapshot(m, monkeypatch):
    from contextlib import closing
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    with closing(m.raw_db()) as db:
        ts = m.now_iso()
        cur = db.execute(
            "INSERT INTO monitors (cert_alias, cert_pem, issuer_pem, crl_uri, tests, "
            "frequency_min, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ("snap", _pem(leaf), _pem(ca), "http://crl.test/ca.crl",
             ",".join(DEFAULTS), 60, ts, ts),
        )
        rid = cur.lastrowid
        db.commit()
        _stub_download(m, monkeypatch,
                       _make_crl(ca_key, ca, crl_number=3,
                                 revoked_serials=[111, 222]))
        row = db.execute("SELECT * FROM monitors WHERE id=?", (rid,)).fetchone()
        m.check_monitor(db, row)
        snaps = db.execute("SELECT * FROM crl_snapshots WHERE monitor_id=?",
                           (rid,)).fetchall()
        assert len(snaps) == 1
        assert snaps[0]["status"] == "Valid"
        assert snaps[0]["next_update"] is not None
        # CRL history captures the issuing CA, CRL number, and revoked count.
        assert snaps[0]["crl_number"] == "3"
        assert "Test CA" in (snaps[0]["crl_issuer"] or "")
        assert snaps[0]["revoked_count"] == 2


def test_run_crl_check_captures_issuer_and_revoked_count(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, revoked_serials=[1, 2, 3], crl_number=9)
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", DEFAULTS)
    assert res.revoked_count == 3
    assert res.crl_number == 9
    assert res.crl_issuer and "CN=" in res.crl_issuer


def test_freshest_crl_urls_extraction(m):
    ca_key, ca = _make_ca()
    base = _make_crl(ca_key, ca, crl_number=10, freshest="http://crl.test/delta.crl")
    assert m._freshest_crl_urls(base) == ["http://crl.test/delta.crl"]


def test_delta_crl_applied_detects_revocation(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca, serial=7777)
    base = _make_crl(ca_key, ca, crl_number=10, freshest="http://crl.test/delta.crl")
    delta = _make_crl(ca_key, ca, revoked_serials=[7777], crl_number=11,
                      delta_indicator=10)
    base_der = base.public_bytes(serialization.Encoding.DER)
    delta_der = delta.public_bytes(serialization.Encoding.DER)

    def fake(url, timeout, max_bytes):
        return 200, (delta_der if "delta" in url else base_der), False
    monkeypatch.setattr(m, "_download_crl", fake)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["delta_crl"])
    # The serial is revoked only in the delta; applying the delta -> Revoked.
    assert res.status == "Revoked", res.message
    dc = next(c for c in res.checks if c["key"] == "delta_crl")
    assert dc["status"] == "pass"
    cs = next(c for c in res.checks if c["key"] == "cert_status")
    assert cs["status"] == "fail"


def test_delta_crl_no_pointer_passes(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca)
    crl = _make_crl(ca_key, ca, crl_number=5)  # no Freshest CRL pointer
    _stub_download(m, monkeypatch, crl)

    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl",
                          DEFAULTS + ["delta_crl"])
    assert res.status == "Valid", res.message
    dc = next(c for c in res.checks if c["key"] == "delta_crl")
    assert dc["status"] == "pass"


def test_deselecting_cert_status_keeps_revoked_off_status(m, monkeypatch):
    ca_key, ca = _make_ca()
    leaf = _make_leaf(ca_key, ca, serial=999)
    crl = _make_crl(ca_key, ca, revoked_serials=[999])
    _stub_download(m, monkeypatch, crl)

    tests = [t for t in DEFAULTS if t != "cert_status"]
    res = m.run_crl_check(_pem(leaf), _pem(ca), "http://crl.test/ca.crl", tests)
    # Revocation is no longer evaluated, so the monitor is Valid.
    assert res.status == "Valid", res.message
