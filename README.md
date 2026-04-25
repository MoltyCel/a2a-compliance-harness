# a2a-compliance-harness

Bounded-scope signature-verification harness for A2A Agent Cards. v0.1.

Runs five sequential checks against an A2A Agent Card URL and emits one JSON row per agent probed. Intended as a reference implementation for the Agent-Card-level identity/signature checks baronsengir007's `exp-055` dataset identified as the Layer 1 measurement gap.

## Scope

1. **Fetch Agent Card** — HTTP GET, capture status, content-type, latency.
2. **Resolve issuer DID** — supports `did:web` (via HTTPS) and `did:key` (via multibase decode). Unknown DID methods yield a `did_resolver_unsupported` marker and the row continues with whatever checks still apply.
3. **Verify signature** — RFC 8785 JCS canonicalization + Ed25519. On failure, classifies as one of:
   - `format_drift` — signature verifies against non-canonical bytes
   - `key_mismatch` — signature verifies against a different advertised key
   - `tampered` — no advertised key verifies under any attempted canonicalization
4. **Walk delegation chain** — if `delegation_chain` is present, each hop must be signed by the prior hop's key, each scope must be a subset of the parent, and each validity window must nest inside the parent's.
5. **Emit row** — a single JSON object per probe.

Out of scope for v0.1: multi-issuer verifier behavior, compliance report generation, DID method registry, behavioral trust scoring.

## Row schema (v0.1)

```json
{
  "probed_at": "2026-04-21T17:00:00Z",
  "agent_card_url": "https://example.com/.well-known/agent-card.json",
  "card_fetched": true,
  "fetch_latency_ms": 127,
  "issuer_did": "did:web:example.com",
  "did_resolved": true,
  "did_resolver_unsupported": false,
  "signature_present": true,
  "signature_valid": true,
  "signature_failure_mode": null,
  "delegation_chain_present": false,
  "delegation_chain_valid": null,
  "delegation_failure_mode": null,
  "overall_compliance": "pass",
  "harness_version": "0.1.0",
  "notes": []
}
```

`overall_compliance` is one of: `pass` / `fail_layer_0` (card unreachable) / `fail_signature` / `fail_delegation` / `partial` (some checks passed, some unsupported).

### Why this shape and not exp-055's v1.1 row

The [OpenClaw v1.1 dataset](https://gist.github.com/baronsengir007/2a0573ad5301bd22c62f8ce0d8c892b7) is experiment-level (one row per measurement run: `exp-055`, `exp-074`, …) with variable layer-specific fields. The harness emits per-agent probe rows, a finer granularity than the v1.1 dataset captures. v0.2 will align the two once we have a joint overlap dataset — see baronsengir007's joint-benchmark proposal in [a2aproject/A2A#1755](https://github.com/a2aproject/A2A/issues/1755).

## Install

```bash
pip install -e ".[dev]"
```

## Usage

### Probe a live Agent Card

```bash
python harness.py --url https://example.com/.well-known/agent-card.json
```

### Run against a fixture (offline)

```bash
python harness.py --fixture fixtures/happy-path.json
```

## Fixtures

Four fixtures demonstrate happy path plus each failure classification:

| File | What it proves |
|------|----------------|
| `fixtures/happy-path.json` | Valid Ed25519 signature over JCS-canonical bytes |
| `fixtures/signature-invalid-format-drift.json` | Signer used `JSON.stringify`, not JCS |
| `fixtures/signature-invalid-key-mismatch.json` | Card's `kid` points at key-B but body is signed by key-A |
| `fixtures/signature-invalid-tampered.json` | Happy-path card modified post-sign |

Each fixture embeds its expected harness output in an `expected_row` field. Tests assert the harness output matches `expected_row` byte-for-byte.

### Regenerating fixtures

All Ed25519 seeds in `tools/generate_fixtures.py` are **test-only deterministic values**. Never reuse them in production. To regenerate after a schema change:

```bash
python tools/generate_fixtures.py
```

## Agent Card shape assumed by the harness

The A2A protocol does not yet specify a signed-Agent-Card wire format. The harness assumes:

```json
{
  "name": "...",
  "description": "...",
  "issuer": "did:web:example.com",
  "capabilities": ["..."],
  "schema_version": "a2a/0.3.0",
  "signature": {
    "alg": "EdDSA",
    "kid": "did:web:example.com#key-1",
    "value": "<base64url Ed25519 over JCS(card_without_signature)>"
  },
  "delegation_chain": [
    {
      "issuer": "did:web:parent.example.com#key-1",
      "subject": "did:web:child.example.com",
      "scope": ["summarize"],
      "not_before": "2026-04-20T00:00:00Z",
      "not_after": "2026-05-20T00:00:00Z",
      "signature": {"alg": "EdDSA", "kid": "...", "value": "..."}
    }
  ]
}
```

Detached-signature style: the `signature` field is stripped before canonicalization; the `value` is an Ed25519 signature over the JCS bytes of the remaining object.

## Development

```bash
ruff check .
pytest -v
```

## Non-goals

- Do not import `agent-passport-system` or any other identity SDK. The harness is deliberately standalone so any A2A consumer can drop it in.
- Do not generate compliance reports, aggregate dashboards, or registry-wide scorecards. One row per probe is the entire output surface.
- Do not invent new DID methods or signature algorithms. Ed25519 + JCS + did:web/did:key only.

## Optional: MolTrust resolver

The harness ships standalone but supports an optional DID resolver backed by the [MolTrust](https://moltrust.ch) SDK. When installed, it routes `did:moltrust:*` (native and bridge-resolved `ext_*`) and `did:web:*` through `api.moltrust.ch`, while falling through to the harness's own `DidResolver` for `did:key:*` and other methods.

```bash
pip install a2a-compliance-harness[moltrust]
```

```python
from moltrust_adapter import MolTrustDidResolver
from harness import probe

with MolTrustDidResolver() as resolver:
    row = probe(
        "https://example.com/.well-known/agent-card.json",
        resolver=resolver,
    )
```

The harness itself does not import the moltrust SDK — `harness.py` stays free of identity-vendor dependencies per the standalone-by-design principle. The adapter (`moltrust_adapter.py`) is opt-in via the `[moltrust]` extra.

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.
