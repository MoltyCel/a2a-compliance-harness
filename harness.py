"""A2A compliance harness — v0.1.

Runs five sequential checks against an A2A Agent Card URL and emits one JSON row
per agent probed. Bounded scope by design: this harness verifies signatures and
delegation-chain structure, nothing else.

Usage:
    python harness.py --fixture fixtures/happy-path.json
    python harness.py --url https://example.com/.well-known/agent-card.json

See README.md for the five-step spec and row schema.

Standalone: this module intentionally does not depend on
`agent-passport-system`. Any A2A consumer can drop harness.py into their repo
without buying into APS.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field

HARNESS_VERSION = "0.1.0"

ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


# ---------------------------------------------------------------------------
# Row schema
# ---------------------------------------------------------------------------


class Row(BaseModel):
    """v0.1 probe row. See README for field semantics."""

    probed_at: str
    agent_card_url: str
    card_fetched: bool
    fetch_latency_ms: int | None = None
    issuer_did: str | None = None
    did_resolved: bool | None = None
    did_resolver_unsupported: bool = False
    signature_present: bool = False
    signature_valid: bool | None = None
    signature_failure_mode: str | None = None
    delegation_chain_present: bool = False
    delegation_chain_valid: bool | None = None
    delegation_failure_mode: str | None = None
    overall_compliance: str = "fail_layer_0"
    harness_version: str = HARNESS_VERSION
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# RFC 8785 JCS canonicalization (subset sufficient for the harness)
# ---------------------------------------------------------------------------


def jcs_canonicalize(value: Any) -> bytes:
    """Canonicalize a JSON-compatible value per RFC 8785 JCS.

    This is a pragmatic subset: sorted keys, minimal whitespace, UTF-8 encoding,
    no-ASCII-escape. Numeric serialization uses Python's default `json` repr,
    which matches JCS for integers and the common float cases we exercise in
    fixtures. Strict float handling per ECMA-262 is not implemented because the
    v0.1 fixtures use integers only.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def non_canonical_default(value: Any) -> bytes:
    """Python `json.dumps` default output — used to detect format drift.

    This matches what a naive implementation produces when it calls
    `JSON.stringify(obj)` / `json.dumps(obj)` with no canonicalization.
    """
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Multibase / did:key decoding
# ---------------------------------------------------------------------------


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc_decode(s: str) -> bytes:
    if not s:
        return b""
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58btc char: {ch!r}")
        n = n * 58 + idx
    # count leading '1' chars (each encodes a zero byte)
    n_leading = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * n_leading + raw


def base58btc_encode(data: bytes) -> str:
    n_leading = len(data) - len(data.lstrip(b"\x00"))
    n = int.from_bytes(data, "big") if data else 0
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    return "1" * n_leading + out


def decode_multibase_ed25519(key_multibase: str) -> bytes:
    """Decode a publicKeyMultibase string that MUST start with 'z' and hold an
    Ed25519 pubkey (multicodec prefix 0xed01)."""
    if not key_multibase.startswith("z"):
        raise ValueError(f"unsupported multibase prefix: {key_multibase[:1]!r}")
    decoded = base58btc_decode(key_multibase[1:])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("not an Ed25519 multicodec key")
    return decoded[len(ED25519_MULTICODEC_PREFIX) :]


def decode_did_key_ed25519(did: str) -> bytes:
    """Decode an Ed25519 public key embedded in a did:key URI."""
    if not did.startswith("did:key:"):
        raise ValueError(f"not a did:key: {did}")
    return decode_multibase_ed25519(did.removeprefix("did:key:"))


# ---------------------------------------------------------------------------
# Ed25519 verification helpers
# ---------------------------------------------------------------------------


@dataclass
class VerificationKey:
    """An Ed25519 public key associated with a DID verification method."""

    kid: str
    raw_pubkey: bytes

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.raw_pubkey).verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


def extract_keys_from_did_document(did_doc: dict[str, Any]) -> list[VerificationKey]:
    """Pull out Ed25519 verification methods from a DID document."""
    keys: list[VerificationKey] = []
    for vm in did_doc.get("verificationMethod", []) or []:
        kid = vm.get("id")
        if not kid:
            continue
        pk_mb = vm.get("publicKeyMultibase")
        if pk_mb:
            try:
                raw = decode_multibase_ed25519(pk_mb)
                keys.append(VerificationKey(kid=kid, raw_pubkey=raw))
                continue
            except ValueError:
                pass
        pk_b64 = vm.get("publicKeyBase64")
        if pk_b64:
            try:
                raw = base64.urlsafe_b64decode(pk_b64 + "=" * (-len(pk_b64) % 4))
                if len(raw) == 32:
                    keys.append(VerificationKey(kid=kid, raw_pubkey=raw))
            except ValueError:
                pass
    return keys


# ---------------------------------------------------------------------------
# DID resolution
# ---------------------------------------------------------------------------


def resolve_did_web_url(did: str) -> str:
    """Map a did:web identifier to the URL of its DID document."""
    if not did.startswith("did:web:"):
        raise ValueError(f"not a did:web: {did}")
    ident = did.removeprefix("did:web:")
    # did:web:example.com:agent:xyz  →  https://example.com/agent/xyz/did.json
    # did:web:example.com            →  https://example.com/.well-known/did.json
    # colons are path separators; percent-encoded hosts are not supported in v0.1.
    parts = ident.split(":")
    host = parts[0]
    if len(parts) == 1:
        return f"https://{host}/.well-known/did.json"
    path = "/".join(parts[1:])
    return f"https://{host}/{path}/did.json"


class DidResolver:
    """Resolves DIDs to DID documents. Fixture mode uses an in-memory map;
    live mode uses HTTP for did:web and direct decoding for did:key."""

    def __init__(self, fixture_docs: dict[str, dict[str, Any]] | None = None):
        self.fixture_docs = fixture_docs or {}

    def resolve(self, did: str) -> tuple[dict[str, Any] | None, str | None]:
        """Return (did_document, error). `error` is None on success or one of:
        - "did_resolver_unsupported"
        - "did_resolution_failed"
        """
        # strip fragment if caller passed a full DID URL
        base_did = did.split("#", 1)[0]

        # fixture short-circuit
        if base_did in self.fixture_docs:
            return self.fixture_docs[base_did], None

        if base_did.startswith("did:key:"):
            try:
                raw = decode_did_key_ed25519(base_did)
                key_multibase = "z" + base58btc_encode(ED25519_MULTICODEC_PREFIX + raw)
                synthetic = {
                    "id": base_did,
                    "verificationMethod": [
                        {
                            "id": f"{base_did}#{key_multibase}",
                            "type": "Ed25519VerificationKey2020",
                            "controller": base_did,
                            "publicKeyMultibase": key_multibase,
                        }
                    ],
                }
                return synthetic, None
            except ValueError:
                return None, "did_resolution_failed"

        if base_did.startswith("did:web:"):
            import requests

            url = resolve_did_web_url(base_did)
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    return None, "did_resolution_failed"
                return resp.json(), None
            except Exception:
                return None, "did_resolution_failed"

        return None, "did_resolver_unsupported"


# ---------------------------------------------------------------------------
# Signature classification
# ---------------------------------------------------------------------------


def _signed_payload(card: dict[str, Any]) -> dict[str, Any]:
    """Return the card with the `signature` field stripped — that's what gets
    signed. Detached-signature style."""
    return {k: v for k, v in card.items() if k != "signature"}


def _decode_sig(sig_value: str) -> bytes:
    return base64.urlsafe_b64decode(sig_value + "=" * (-len(sig_value) % 4))


def verify_card_signature(
    card: dict[str, Any],
    keys: list[VerificationKey],
) -> tuple[bool, str | None, str | None]:
    """Verify the card's detached Ed25519 signature.

    Returns (is_valid, failure_mode, notes).
    failure_mode is None on success, or one of:
    - "format_drift" — non-JCS canonicalization matched the claimed key
    - "key_mismatch" — claimed key failed, another advertised key succeeded
    - "tampered"    — no advertised key could verify under any canonicalization
    """
    sig_field = card.get("signature") or {}
    sig_value = sig_field.get("value")
    claimed_kid = sig_field.get("kid")
    if not sig_value:
        return False, "tampered", "signature.value missing"
    try:
        sig_bytes = _decode_sig(sig_value)
    except Exception:
        return False, "tampered", "signature.value not base64url"

    payload = _signed_payload(card)
    jcs_bytes = jcs_canonicalize(payload)
    drift_bytes = non_canonical_default(payload)

    claimed_key = next((k for k in keys if k.kid == claimed_kid), None)

    # Happy path — claimed key verifies JCS bytes
    if claimed_key and claimed_key.verify(jcs_bytes, sig_bytes):
        return True, None, None

    # Format drift — claimed key verifies non-canonical bytes
    if claimed_key and claimed_key.verify(drift_bytes, sig_bytes):
        return False, "format_drift", "signature verified against non-JCS bytes"

    # Key mismatch — another advertised key verifies JCS bytes
    for k in keys:
        if k.kid == claimed_kid:
            continue
        if k.verify(jcs_bytes, sig_bytes):
            return False, "key_mismatch", f"signature verified against {k.kid}, not {claimed_kid}"

    # Tampered — no advertised key verifies under any canonicalization we try
    return False, "tampered", "signature did not verify against any advertised key"


# ---------------------------------------------------------------------------
# Delegation chain walker
# ---------------------------------------------------------------------------


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        # support trailing Z
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def walk_delegation_chain(
    chain: list[dict[str, Any]],
    root_keys: list[VerificationKey],
    resolver: DidResolver,
) -> tuple[bool, str | None]:
    """Walk a delegation chain enforcing signature validity, monotonic scope
    narrowing, and nested validity windows.

    Returns (chain_valid, failure_mode). failure_mode is one of:
    - "delegation_invalid_signature"
    - "delegation_invalid_scope_widening"
    - "delegation_invalid_window"
    """
    parent_keys = root_keys
    parent_scope: set[str] | None = None
    parent_nb: datetime | None = None
    parent_na: datetime | None = None

    for hop in chain:
        sig_field = hop.get("signature") or {}
        sig_value = sig_field.get("value")
        claimed_kid = sig_field.get("kid")
        if not sig_value:
            return False, "delegation_invalid_signature"
        try:
            sig_bytes = _decode_sig(sig_value)
        except Exception:
            return False, "delegation_invalid_signature"

        payload = {k: v for k, v in hop.items() if k != "signature"}
        jcs_bytes = jcs_canonicalize(payload)

        signer = next((k for k in parent_keys if k.kid == claimed_kid), None)
        if not signer or not signer.verify(jcs_bytes, sig_bytes):
            return False, "delegation_invalid_signature"

        scope = set(hop.get("scope") or [])
        if parent_scope is not None and not scope.issubset(parent_scope):
            return False, "delegation_invalid_scope_widening"

        nb = _parse_iso(hop.get("not_before"))
        na = _parse_iso(hop.get("not_after"))
        if nb and na and nb > na:
            return False, "delegation_invalid_window"
        if parent_nb and nb and nb < parent_nb:
            return False, "delegation_invalid_window"
        if parent_na and na and na > parent_na:
            return False, "delegation_invalid_window"

        # next hop must be signed by this subject's key
        subject_did = hop.get("subject")
        if subject_did:
            doc, err = resolver.resolve(subject_did)
            if err or doc is None:
                return False, "delegation_invalid_signature"
            parent_keys = extract_keys_from_did_document(doc)
        parent_scope = scope
        parent_nb = nb or parent_nb
        parent_na = na or parent_na

    return True, None


# ---------------------------------------------------------------------------
# Core probe (shared between live and fixture paths)
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _probe_core(
    agent_card_url: str,
    card: dict[str, Any] | None,
    fetch_latency_ms: int | None,
    card_fetched: bool,
    resolver: DidResolver,
    probed_at: str | None = None,
) -> Row:
    row = Row(
        probed_at=probed_at or _now_iso(),
        agent_card_url=agent_card_url,
        card_fetched=card_fetched,
        fetch_latency_ms=fetch_latency_ms,
    )

    if not card_fetched or card is None:
        row.overall_compliance = "fail_layer_0"
        return row

    # Step 2 — resolve issuer DID
    issuer = card.get("issuer")
    row.issuer_did = issuer
    if not issuer:
        row.did_resolved = False
        row.overall_compliance = "fail_signature"
        row.notes.append("card has no issuer field")
        return row

    did_doc, err = resolver.resolve(issuer)
    if err == "did_resolver_unsupported":
        row.did_resolver_unsupported = True
        row.did_resolved = False
        row.overall_compliance = "partial"
        row.notes.append(f"unsupported DID method for {issuer}")
        return row
    if err or did_doc is None:
        row.did_resolved = False
        row.overall_compliance = "fail_signature"
        row.notes.append(f"DID resolution failed for {issuer}")
        return row
    row.did_resolved = True
    keys = extract_keys_from_did_document(did_doc)

    # Step 3 — verify signature
    row.signature_present = bool(card.get("signature"))
    if not row.signature_present:
        row.signature_valid = False
        row.signature_failure_mode = "tampered"
        row.notes.append("card has no signature field")
        row.overall_compliance = "fail_signature"
        return row

    valid, mode, note = verify_card_signature(card, keys)
    row.signature_valid = valid
    row.signature_failure_mode = mode
    if note:
        row.notes.append(note)

    # Step 4 — walk delegation chain if present
    chain = card.get("delegation_chain") or []
    row.delegation_chain_present = bool(chain)
    if chain:
        chain_valid, chain_mode = walk_delegation_chain(chain, keys, resolver)
        row.delegation_chain_valid = chain_valid
        row.delegation_failure_mode = chain_mode

    # Step 5 — overall verdict
    if row.signature_valid is False:
        row.overall_compliance = "fail_signature"
    elif row.delegation_chain_present and row.delegation_chain_valid is False:
        row.overall_compliance = "fail_delegation"
    elif row.did_resolver_unsupported:
        row.overall_compliance = "partial"
    else:
        row.overall_compliance = "pass"

    return row


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def probe(agent_card_url: str, *, timeout: float = 10.0) -> Row:
    """Probe a live A2A Agent Card URL over HTTP."""
    import requests

    t0 = time.perf_counter()
    try:
        resp = requests.get(agent_card_url, timeout=timeout)
        fetch_ms = int((time.perf_counter() - t0) * 1000)
        if resp.status_code != 200:
            return _probe_core(agent_card_url, None, fetch_ms, False, DidResolver())
        try:
            card = resp.json()
        except ValueError:
            return _probe_core(agent_card_url, None, fetch_ms, False, DidResolver())
    except Exception:
        fetch_ms = int((time.perf_counter() - t0) * 1000)
        return _probe_core(agent_card_url, None, fetch_ms, False, DidResolver())

    return _probe_core(agent_card_url, card, fetch_ms, True, DidResolver())


def probe_from_fixture(fixture_path: str | Path) -> Row:
    """Probe using a local fixture bundle — no network calls.

    The fixture is a JSON file with keys:
    - `agent_card_url` — the URL the card would be served from
    - `card` — the Agent Card JSON
    - `did_documents` — map of DID → DID document
    - `fetch_latency_ms` (optional)
    - `card_fetched` (optional, default true)
    - `probed_at` (optional, used for deterministic expected_row)
    """
    fixture_path = Path(fixture_path)
    bundle = json.loads(fixture_path.read_text())
    resolver = DidResolver(fixture_docs=bundle.get("did_documents") or {})
    return _probe_core(
        agent_card_url=bundle["agent_card_url"],
        card=bundle.get("card"),
        fetch_latency_ms=bundle.get("fetch_latency_ms", 0),
        card_fetched=bundle.get("card_fetched", True),
        resolver=resolver,
        probed_at=bundle.get("probed_at"),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A2A compliance harness v" + HARNESS_VERSION)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Live Agent Card URL to probe")
    group.add_argument("--fixture", help="Path to a local fixture bundle")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)

    if args.url:
        row = probe(args.url, timeout=args.timeout)
    else:
        row = probe_from_fixture(args.fixture)

    print(json.dumps(row.model_dump(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
