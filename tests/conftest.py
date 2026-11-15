"""Shared test configuration.

The app now fails closed: with no authentication configured it refuses to start
unless open mode is explicitly enabled. The engine/security test suites exercise
the app in its original single-user mode, so default to open mode for them. The
auth tests override this per-test via ``monkeypatch`` to cover the refusal, local
login, and OIDC paths.
"""
import os

os.environ.setdefault("CRL_ALLOW_OPEN_MODE", "true")
