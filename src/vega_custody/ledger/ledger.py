"""ledger.py - ledger-agnostic mint + verify. The commitment record is a hash-chained file replicated to every
configured backend (local disk, USB/external drive); an optional public witness anchors Merkle roots of batches.

What is stored: the commitment's allow-listed metadata and its hash. Never the action's parameters, never keys.
Mint is atomic across replicas (record-or-refuse). verify() re-reads the ledger off disk and fails closed."""
import os
import sys

from vega_custody.dag.dag import Chain, DagError, canonical, sha256_hex  # noqa: E402
from vega_custody.ledger import merkle  # noqa: E402
from vega_custody.ledger.backend_local import BackendUnavailable  # noqa: E402

META_FIELDS = frozenset({"kind", "device", "surface", "action", "action_hash", "expiry", "nonce_sha256", "nonce", "signature"})
REQUIRED_FIELDS = ("action", "action_hash", "expiry", "nonce_sha256")


class LedgerError(Exception):
    pass


class LedgerUnavailable(LedgerError):
    pass


class LedgerRefused(LedgerError):
    pass


def leaf_of(commitment: dict) -> str:
    return sha256_hex(canonical(commitment))


class Ledger:
    def __init__(self, backends, witness=None, batch_size=64, commitment_check=None):
        """commitment_check: fn(commitment) -> bool for commitments of kind WCOMMIT. When given, a WCOMMIT is minted and verified ONLY if its human signature checks out (use
        vega_jacket.humanauth.verify.commitment_signature_checker(public_key)). Without it the ledger trusts whoever holds mint(): hand gates reader() and keep mint inside the commit step."""
        self._commitment_check = commitment_check
        paths, self.degraded = [], []
        for b in backends:
            try:
                b.check()
                paths.append(b.path)
            except BackendUnavailable as exc:
                if b.required:
                    raise LedgerUnavailable(f"required backend unavailable: {exc}") from exc
                self.degraded.append(b.name)
        if not paths:
            raise LedgerUnavailable("no backend available")
        try:
            self.chain = Chain(paths)
        except DagError as exc:
            raise LedgerUnavailable(f"ledger refused to open: {exc}") from exc
        self.witness, self.batch_size = witness, batch_size
        self._leaves = {e["payload"]["leaf"]: e["entry_hash"] for e in self.chain.entries() if e["kind"] == "MINT"}
        anchors = [e for e in self.chain.entries() if e["kind"] == "ANCHOR"]
        self._anchored_upto = anchors[-1]["payload"]["last_seq"] if anchors else -1

    # ------------------------------------------------------------------ mint
    def mint(self, commitment: dict) -> dict:
        extra = set(commitment) - META_FIELDS
        if extra:
            raise LedgerRefused(f"commitment carries non-metadata field(s) {sorted(extra)}: hashes and metadata only")
        for f in REQUIRED_FIELDS:
            if f not in commitment:
                raise LedgerRefused(f"commitment missing {f}")
        if self._commitment_check is not None and commitment.get("kind") == "WCOMMIT" and not self._safe_check(commitment):
            raise LedgerRefused("a WCOMMIT must carry a valid human signature: refusing to mint a commitment the human key did not sign")
        leaf = leaf_of(commitment)
        if leaf in self._leaves:
            raise LedgerRefused("already minted (a commitment is single use)")
        try:
            e = self.chain.record("MINT", {"leaf": leaf, "commitment": commitment})
        except DagError as exc:
            raise LedgerRefused(f"mint refused, nothing recorded: {exc}") from exc
        self._leaves[leaf] = e["entry_hash"]
        receipt = {"leaf": leaf, "entry": e["entry_hash"], "seq": e["seq"],
                   "replicas": len(self.chain.paths), "degraded": list(self.degraded)}
        if self.witness is not None and self._pending_count() >= self.batch_size:
            try:
                receipt["anchor"] = self.anchor_pending()
            except Exception as exc:  # the mint stands; the anchor is retried on the next batch
                receipt["anchor_error"] = f"{type(exc).__name__}: {exc}"
        return receipt

    def _safe_check(self, commitment) -> bool:
        try:
            return self._commitment_check(commitment) is True
        except Exception:  # reviewed: a checker that fails does not approve the commitment
            return False

    def reader(self):
        """A read-only view (verify and inclusion_proof, no mint). Hand THIS to gates and contained code: whoever holds mint can fabricate a commitment that verifies,
        so mint belongs only to the commit step that checked a human signature."""
        return ReadOnlyLedger(self)

    # ---------------------------------------------------------------- verify
    def verify(self, commitment: dict) -> bool:
        """True only if this exact commitment is in the ledger and the whole ledger (all replicas) is intact."""
        try:
            ok, _ = self.chain.verify()
            if not ok:
                return False
            if self._commitment_check is not None and isinstance(commitment, dict) and commitment.get("kind") == "WCOMMIT" and not self._safe_check(commitment):
                return False
            leaf = leaf_of(commitment)
            return any(r["kind"] == "MINT" and r["payload"]["leaf"] == leaf for r in self.chain.read_primary())
        except Exception:
            return False

    # ---------------------------------------------------------------- anchor
    def _pending(self):
        return [e for e in self.chain.entries() if e["kind"] == "MINT" and e["seq"] > self._anchored_upto]

    def _pending_count(self):
        return len(self._pending())

    def anchor_pending(self):
        if self.witness is None:
            raise LedgerError("no witness configured")
        pending = self._pending()
        if not pending:
            return None
        leaves = [bytes.fromhex(e["payload"]["leaf"]) for e in pending]
        rt = merkle.root(leaves).hex()
        receipt = self.witness.anchor(rt)
        last = pending[-1]["seq"]
        self.chain.record("ANCHOR", {"root": rt, "count": len(leaves), "first_seq": pending[0]["seq"],
                                      "last_seq": last, "witness": receipt})
        self._anchored_upto = last
        return {"root": rt, "count": len(leaves), "witness": receipt}

    def inclusion_proof(self, commitment: dict):
        """Merkle path from this commitment to the root of the anchor batch that covers it, or None."""
        leaf = leaf_of(commitment)
        rows = self.chain.entries()
        lo = -1
        for a in (r for r in rows if r["kind"] == "ANCHOR"):
            batch = [r for r in rows if r["kind"] == "MINT" and lo < r["seq"] <= a["payload"]["last_seq"]]
            hashes = [r["payload"]["leaf"] for r in batch]
            if leaf in hashes:
                leaves = [bytes.fromhex(h) for h in hashes]
                return {"root": a["payload"]["root"], "path": merkle.proof(leaves, hashes.index(leaf)),
                        "leaf": leaf}
            lo = a["payload"]["last_seq"]
        return None


class ReadOnlyLedger:
    """Exposes verify() and inclusion_proof() only. It holds no mint, no anchor and no chain handle."""

    __slots__ = ("verify", "inclusion_proof")

    def __init__(self, ledger):
        object.__setattr__(self, "verify", ledger.verify)
        object.__setattr__(self, "inclusion_proof", ledger.inclusion_proof)
