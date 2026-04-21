"""Regenerate the four test fixtures under fixtures/.

All Ed25519 private-key seeds in this file are TEST-ONLY deterministic values.
They MUST NOT be reused in production. They exist so the fixtures hash-match
across machines and give CI something stable to verify against.

Run from the repo root:

    python tools/generate_fixtures.py

Requires `cryptography` (see pyproject.toml).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from harness import (  # noqa: E402
    ED25519_MULTICODEC_PREFIX,
    base58btc_encode,
    jcs_canonicalize,
    non_canonical_default,
)

# TEST-ONLY seeds. Never reuse in production. Each is 32 bytes of hex.
SEED_A = bytes.fromhex("a0" * 32)
SEED_B = bytes.fromhex("b1" * 32)
SEED_C = bytes.fromhex("c2" * 32)

FIXED_PROBED_AT = "2026-04-21T17:00:00Z"
AGENT_CARD_URL = "https://example.com/.well-known/agent-card.json"
ISSUER_DID = "did:web:example.com"


def keypair(seed: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def multibase_ed25519(pk_raw: bytes) -> str:
    return "z" + base58btc_encode(ED25519_MULTICODEC_PREFIX + pk_raw)


def verification_method(kid: str, controller: str, pk_raw: bytes) -> dict:
    return {
        "id": kid,
        "type": "Ed25519VerificationKey2020",
        "controller": controller,
        "publicKeyMultibase": multibase_ed25519(pk_raw),
    }


def base_card() -> dict:
    return {
        "name": "Example Compliance Agent",
        "description": "Reference A2A agent for harness fixtures.",
        "issuer": ISSUER_DID,
        "capabilities": ["summarize", "translate"],
        "schema_version": "a2a/0.3.0",
    }


def write_fixture(name: str, bundle: dict) -> None:
    out = REPO_ROOT / "fixtures" / f"{name}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"wrote {out.relative_to(REPO_ROOT)}")


def run_harness(fixture_name: str) -> dict:
    """Run probe_from_fixture and return the row as a dict."""
    from harness import probe_from_fixture

    row = probe_from_fixture(REPO_ROOT / "fixtures" / f"{fixture_name}.json")
    return row.model_dump()


def build_happy_path() -> None:
    sk_a, pk_a = keypair(SEED_A)
    kid = f"{ISSUER_DID}#key-1"
    did_doc = {
        "id": ISSUER_DID,
        "verificationMethod": [verification_method(kid, ISSUER_DID, pk_a)],
        "authentication": [kid],
    }
    card = base_card()
    signed_bytes = jcs_canonicalize(card)
    sig = sk_a.sign(signed_bytes)
    card["signature"] = {"alg": "EdDSA", "kid": kid, "value": b64url(sig)}

    bundle = {
        "description": "valid Ed25519 signature over JCS-canonical bytes",
        "agent_card_url": AGENT_CARD_URL,
        "card_fetched": True,
        "fetch_latency_ms": 127,
        "probed_at": FIXED_PROBED_AT,
        "card": card,
        "did_documents": {ISSUER_DID: did_doc},
    }
    write_fixture("happy-path", bundle)
    row = run_harness("happy-path")
    bundle["expected_row"] = row
    write_fixture("happy-path", bundle)


def build_format_drift() -> None:
    sk_a, pk_a = keypair(SEED_A)
    kid = f"{ISSUER_DID}#key-1"
    did_doc = {
        "id": ISSUER_DID,
        "verificationMethod": [verification_method(kid, ISSUER_DID, pk_a)],
        "authentication": [kid],
    }
    card = base_card()
    # Sign default-serialized bytes (no JCS) — the drift we're detecting.
    sig = sk_a.sign(non_canonical_default(card))
    card["signature"] = {"alg": "EdDSA", "kid": kid, "value": b64url(sig)}

    bundle = {
        "description": "signature produced over json.dumps() default output, not JCS",
        "agent_card_url": AGENT_CARD_URL,
        "card_fetched": True,
        "fetch_latency_ms": 131,
        "probed_at": FIXED_PROBED_AT,
        "card": card,
        "did_documents": {ISSUER_DID: did_doc},
    }
    write_fixture("signature-invalid-format-drift", bundle)
    row = run_harness("signature-invalid-format-drift")
    bundle["expected_row"] = row
    write_fixture("signature-invalid-format-drift", bundle)


def build_key_mismatch() -> None:
    # Claimed kid points at key B+C (in DID doc), but signature is actually by A.
    sk_a, pk_a = keypair(SEED_A)
    _, pk_b = keypair(SEED_B)
    _, pk_c = keypair(SEED_C)

    kid_b = f"{ISSUER_DID}#key-b"
    kid_c = f"{ISSUER_DID}#key-c"

    did_doc = {
        "id": ISSUER_DID,
        "verificationMethod": [
            verification_method(kid_b, ISSUER_DID, pk_b),
            verification_method(kid_c, ISSUER_DID, pk_c),
            # secretly, key A is ALSO advertised — but the card's `kid` claims key-b.
            # This mirrors the "signed with a different advertised key than claimed" case.
            verification_method(f"{ISSUER_DID}#key-a", ISSUER_DID, pk_a),
        ],
        "authentication": [kid_b, kid_c],
    }
    card = base_card()
    signed_bytes = jcs_canonicalize(card)
    sig = sk_a.sign(signed_bytes)
    card["signature"] = {"alg": "EdDSA", "kid": kid_b, "value": b64url(sig)}

    bundle = {
        "description": "card claims kid=key-b but is actually signed by key-a",
        "agent_card_url": AGENT_CARD_URL,
        "card_fetched": True,
        "fetch_latency_ms": 118,
        "probed_at": FIXED_PROBED_AT,
        "card": card,
        "did_documents": {ISSUER_DID: did_doc},
    }
    write_fixture("signature-invalid-key-mismatch", bundle)
    row = run_harness("signature-invalid-key-mismatch")
    bundle["expected_row"] = row
    write_fixture("signature-invalid-key-mismatch", bundle)


def build_tampered() -> None:
    sk_a, pk_a = keypair(SEED_A)
    kid = f"{ISSUER_DID}#key-1"
    did_doc = {
        "id": ISSUER_DID,
        "verificationMethod": [verification_method(kid, ISSUER_DID, pk_a)],
        "authentication": [kid],
    }
    card = base_card()
    signed_bytes = jcs_canonicalize(card)
    sig = sk_a.sign(signed_bytes)
    card["signature"] = {"alg": "EdDSA", "kid": kid, "value": b64url(sig)}
    # Tamper AFTER signing: modify the description. No canonicalization will recover.
    card["description"] = card["description"] + " (tampered)"

    bundle = {
        "description": "happy-path card modified post-sign",
        "agent_card_url": AGENT_CARD_URL,
        "card_fetched": True,
        "fetch_latency_ms": 142,
        "probed_at": FIXED_PROBED_AT,
        "card": card,
        "did_documents": {ISSUER_DID: did_doc},
    }
    write_fixture("signature-invalid-tampered", bundle)
    row = run_harness("signature-invalid-tampered")
    bundle["expected_row"] = row
    write_fixture("signature-invalid-tampered", bundle)


if __name__ == "__main__":
    build_happy_path()
    build_format_drift()
    build_key_mismatch()
    build_tampered()
    print("done.")
