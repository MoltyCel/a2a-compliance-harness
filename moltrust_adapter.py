"""Optional MolTrust adapter for the a2a-compliance-harness.

Bridges the moltrust SDK's exception-based API to the harness's
DidResolver tuple-based API. The harness itself does NOT import
this module — it is opt-in via the ``[moltrust]`` extras install.

Per the harness README's standalone-by-design principle, this
adapter lives in the harness repo (Apache-2.0) but as a separate
module. ``harness.py`` never imports moltrust directly.

Usage::

    pip install a2a-compliance-harness[moltrust]

    from moltrust_adapter import MolTrustDidResolver
    from harness import probe

    with MolTrustDidResolver() as resolver:
        row = probe(
            "https://example.com/.well-known/agent-card.json",
            resolver=resolver,
        )

Coverage:
- did:moltrust:* (native + bridge-resolved ext_*) → resolved via api.moltrust.ch
- did:web:*                                       → resolved via api.moltrust.ch
- did:key:*                                       → falls through to harness's DidResolver
- other methods                                   → falls through to harness's DidResolver

The fall-through ensures that adding the MolTrust adapter never
narrows the resolver's coverage — it only adds the moltrust paths.
"""

from __future__ import annotations

from typing import Any

try:
    from moltrust import MolTrustResolver, ResolutionError
except ImportError as exc:  # pragma: no cover - import-time guard only
    raise ImportError(
        "moltrust SDK is not installed. Install with:\n"
        "    pip install a2a-compliance-harness[moltrust]"
    ) from exc

from harness import DidResolver


class MolTrustDidResolver(DidResolver):
    """DidResolver implementation backed by the moltrust SDK.

    Routes ``did:moltrust:*`` and ``did:web:*`` through the moltrust
    SDK against ``api.moltrust.ch``. Other DID methods fall through
    to the parent ``DidResolver`` (covering ``did:key:*`` natively
    and ``fixture_docs`` in offline mode).

    Args:
        fixture_docs: Optional in-memory map of DID → DID Document, same
            as ``DidResolver``'s constructor. Used for fixture-driven
            offline tests.
        api_url: Base URL of the MolTrust API. Default ``https://api.moltrust.ch``.
        timeout: HTTP timeout in seconds for the MolTrust calls. Default 5.0.
    """

    def __init__(
        self,
        fixture_docs: dict[str, dict[str, Any]] | None = None,
        api_url: str = "https://api.moltrust.ch",
        timeout: float = 5.0,
    ) -> None:
        super().__init__(fixture_docs=fixture_docs)
        self._moltrust = MolTrustResolver(api_url=api_url, timeout=timeout)

    def resolve(self, did: str) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve ``did`` using moltrust for moltrust/web, otherwise fall through.

        Matches the parent's tuple return shape: ``(did_document, error)``.
        On moltrust ResolutionError, maps to ``"did_resolution_failed"``
        (consistent with parent's vocabulary). On
        ``ResolutionError.reason == "methodNotSupported"``, falls through
        to the parent so the parent's ``"did_resolver_unsupported"``
        marker stays authoritative.
        """
        # Strip fragment if caller passed a full DID URL — parent does
        # this too; keep the same behavior here for parity.
        base_did = did.split("#", 1)[0]

        # Fixture short-circuit (matches parent precedence)
        if base_did in self.fixture_docs:
            return self.fixture_docs[base_did], None

        if base_did.startswith("did:moltrust:") or base_did.startswith("did:web:"):
            try:
                doc = self._moltrust.resolve(base_did)
            except ResolutionError as e:
                if e.reason == "methodNotSupported":
                    # Defer to parent so harness's vocabulary owns this case
                    return super().resolve(did)
                if e.reason == "notFound":
                    return None, "did_resolution_failed"
                # network errors, invalidDid, didNotResolved
                return None, "did_resolution_failed"
            return doc.to_dict(), None

        # Other methods (did:key, etc.) → parent handles natively
        return super().resolve(did)

    def close(self) -> None:
        """Release the underlying moltrust HTTP client."""
        self._moltrust.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
