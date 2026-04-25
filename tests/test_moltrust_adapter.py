"""Tests for the optional MolTrust adapter.

Skipped entirely if ``moltrust`` is not installed (i.e. when the user
installs the harness without the ``[moltrust]`` extra).

The live tests hit ``api.moltrust.ch`` and are skipped if network is
unavailable. Set ``MOLTRUST_API_URL`` to override the API base.
"""

from __future__ import annotations

import os

import pytest

# Skip the entire module if moltrust isn't installed.
moltrust = pytest.importorskip(
    "moltrust",
    reason="moltrust SDK not installed; install with [moltrust] extra",
)

from moltrust_adapter import MolTrustDidResolver  # noqa: E402

API_URL = os.getenv("MOLTRUST_API_URL", "https://api.moltrust.ch")
TRUSTSCOUT_DID = "did:moltrust:d34ed796a4dc4698"


@pytest.mark.live
def test_adapter_resolves_did_moltrust_native():
    """Live: did:moltrust:* native resolution returns the agent's document."""
    with MolTrustDidResolver(api_url=API_URL) as resolver:
        doc, error = resolver.resolve(TRUSTSCOUT_DID)
    assert error is None
    assert doc is not None
    assert doc.get("id") == TRUSTSCOUT_DID


@pytest.mark.live
def test_adapter_resolves_did_web_self():
    """Live: did:web:api.moltrust.ch resolves via the MolTrust API."""
    with MolTrustDidResolver(api_url=API_URL) as resolver:
        doc, error = resolver.resolve("did:web:api.moltrust.ch")
    assert error is None
    assert doc is not None
    assert doc.get("id") == "did:web:api.moltrust.ch"


def test_adapter_falls_through_to_parent_for_did_key():
    """did:key:* must use the harness's parent resolver, not moltrust."""
    # did:key:z6Mk... — built by harness's decode_did_key_ed25519 inline
    did_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    with MolTrustDidResolver(api_url=API_URL) as resolver:
        doc, error = resolver.resolve(did_key)
    # Parent class returns a synthetic doc for did:key — assert success path.
    # Either the doc is built (success) or the parent's classification kicks
    # in cleanly (no moltrust error string leakage).
    assert error in (None, "did_resolution_failed")
    if error is None:
        assert doc is not None
        assert doc.get("id") == did_key


def test_adapter_returns_unsupported_for_other_methods():
    """did:agentnexus is out of moltrust v0.2.0 scope; falls through to parent."""
    with MolTrustDidResolver(api_url=API_URL) as resolver:
        doc, error = resolver.resolve("did:agentnexus:test")
    # Parent's vocabulary should own this — "did_resolver_unsupported"
    assert doc is None
    assert error == "did_resolver_unsupported"


def test_adapter_uses_fixture_docs_short_circuit():
    """When fixture_docs is set, the adapter shouldn't hit the network."""
    fake_doc = {"id": "did:moltrust:abc1234567890def", "verificationMethod": []}
    with MolTrustDidResolver(
        fixture_docs={"did:moltrust:abc1234567890def": fake_doc},
        api_url="https://invalid.localhost",
    ) as resolver:
        doc, error = resolver.resolve("did:moltrust:abc1234567890def")
    assert error is None
    assert doc == fake_doc
