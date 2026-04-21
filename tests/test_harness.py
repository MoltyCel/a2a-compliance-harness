"""Fixture-driven tests for the A2A compliance harness.

Each fixture embeds an `expected_row` — the output the harness should produce
when probing that fixture. The test loads the fixture, runs
`probe_from_fixture`, and asserts the emitted row matches `expected_row`
exactly. A mismatch means either the harness regressed or a fixture needs
regenerating via `tools/generate_fixtures.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness import (
    base58btc_decode,
    base58btc_encode,
    decode_did_key_ed25519,
    jcs_canonicalize,
    probe_from_fixture,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

FIXTURE_NAMES = [
    "happy-path",
    "signature-invalid-format-drift",
    "signature-invalid-key-mismatch",
    "signature-invalid-tampered",
]


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_fixture_matches_expected_row(fixture_name: str) -> None:
    path = FIXTURES_DIR / f"{fixture_name}.json"
    bundle = json.loads(path.read_text())
    expected = bundle["expected_row"]

    row = probe_from_fixture(path)
    actual = row.model_dump()

    assert actual == expected, (
        f"fixture {fixture_name} drifted — regenerate via tools/generate_fixtures.py "
        f"if the change is intentional.\nexpected: {expected}\nactual:   {actual}"
    )


def test_overall_compliance_values_are_bounded() -> None:
    """Guard against stray values in the overall_compliance field."""
    allowed = {"pass", "fail_layer_0", "fail_signature", "fail_delegation", "partial"}
    for name in FIXTURE_NAMES:
        bundle = json.loads((FIXTURES_DIR / f"{name}.json").read_text())
        assert bundle["expected_row"]["overall_compliance"] in allowed


def test_base58btc_roundtrip() -> None:
    for payload in [b"", b"\x00", b"\x00\x01\x02", b"hello", bytes(range(32))]:
        assert base58btc_decode(base58btc_encode(payload)) == payload


def test_did_key_decode() -> None:
    # Known did:key from the W3C test vectors (Ed25519 zero pubkey would be
    # trivial; this uses a real published example).
    did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    raw = decode_did_key_ed25519(did)
    assert len(raw) == 32


def test_jcs_sorts_keys_and_minimizes_whitespace() -> None:
    out = jcs_canonicalize({"b": 2, "a": 1})
    assert out == b'{"a":1,"b":2}'
