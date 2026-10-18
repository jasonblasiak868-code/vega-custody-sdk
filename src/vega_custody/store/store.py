"""store.py - the write gate. A save succeeds only when ALL THREE sources hold the exact bytes, each read back,
the save is scored, and both DAGs have recorded it. Anything less is refused and rolled back (fail closed).

Sources: local, external (a second physical drive), server (cloud or remote). Each is a backend object with
put/get/delete/uri. Content is addressed by sha256 of the serialized capsule."""
import hashlib
import os
import pathlib
import re
import sys

from vega_custody.capsule import capsule as capsule_mod  # noqa: E402

SOURCES = ("local", "external", "server")


class StoreRefused(Exception):
    pass


_KEY = re.compile(r"[0-9a-f]{64}")


class DirBackend:
    """A directory as a source: a local folder, a mounted drive, or a mounted/synced server path."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _p(self, key):
        if not isinstance(key, str) or not _KEY.fullmatch(key.removesuffix(".tmp")):
            raise StoreRefused("object keys are sha256 hex digests; anything else (a path, '..') is refused")
        return self.root / key

    def put(self, key, data: bytes):
        tmp = self._p(key + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, self._p(key))

    def get(self, key):
        p = self._p(key)
        return p.read_bytes() if p.exists() else None

    def delete(self, key):
        try:
            self._p(key).unlink()
        except FileNotFoundError:
            pass

    def uri(self, key):
        return str(self._p(key))


def default_score(c: dict) -> dict:
    """Provenance-completeness score, 0..1. This is a floor, not a quality judgement: plug in your own scorer
    for quality. A save with no score at all is refused regardless of which scorer is used."""
    md = c.get("metadata", {})
    checks = {
        "has_source": bool(md.get("source") or md.get("origin")),
        "has_license_class": bool(md.get("license_class")),
        "has_data": bool(c.get("data_sha256")) and len(c.get("data_b64", "")) > 0,
        "has_timestamp": bool(c.get("utc")),
        "has_lineage": c.get("predecessor") is not None,
    }
    return {"score": sum(checks.values()) / len(checks), "checks": checks, "scorer": "default-provenance-v1"}


class ThreeSourceStore:
    def __init__(self, backends: dict, dag, scorer=default_score, min_score=0.0):
        if set(backends) != set(SOURCES):
            raise StoreRefused(f"exactly these sources are required: {SOURCES}")
        self.backends = dict(backends)
        roots = {}
        for label, b in self.backends.items():
            r = getattr(b, "root", None)
            if r is not None:
                roots[label] = pathlib.Path(r).resolve()
        for a in roots:
            for b2 in roots:
                if a < b2 and (roots[a] == roots[b2] or roots[a] in roots[b2].parents or roots[b2] in roots[a].parents):
                    raise StoreRefused(f"sources '{a}' and '{b2}' are the same folder or nested: three copies in one place are one copy")
        self.dag = dag
        self.scorer = scorer
        self.min_score = min_score

    def save(self, c: dict) -> dict:
        try:
            capsule_mod.verify(c)
        except capsule_mod.CapsuleError as exc:
            raise StoreRefused(f"capsule failed verification: {exc}") from exc
        blob = capsule_mod.to_bytes(c)
        digest = hashlib.sha256(blob).hexdigest()

        scored = self.scorer(c)
        if not isinstance(scored, dict) or not isinstance(scored.get("score"), (int, float)) \
                or not 0.0 <= scored["score"] <= 1.0:
            raise StoreRefused("every save must be scored: scorer returned no valid score")
        if scored["score"] < self.min_score:
            raise StoreRefused(f"score {scored['score']} below minimum {self.min_score}")

        written, entry = [], None
        try:
            for label, b in self.backends.items():
                pre = b.get(digest)
                if pre is not None and hashlib.sha256(pre).hexdigest() != digest:
                    raise StoreRefused(f"{label}: an object with this key exists and does not match")
                if pre is None:
                    b.put(digest, blob)
                    written.append(label)
                back = b.get(digest)
                if back is None or hashlib.sha256(back).hexdigest() != digest:
                    raise StoreRefused(f"{label}: read-back failed")
            entry = self.dag.record("SAVE", {
                "data_sha256": digest,
                "capsule_prefix_hash": c["prefix_hash"],
                "predecessor": c["predecessor"],
                "size_bytes": len(blob),
                "score": scored,
            })
            for label, b in self.backends.items():
                self.dag.record_location(entry["entry_hash"], label, b.uri(digest), digest)
        except Exception as exc:
            for label in written:
                try:
                    self.backends[label].delete(digest)
                except Exception:
                    pass
            if entry is not None:
                try:
                    self.dag.record("SAVE_ABORTED", {"save_entry": entry["entry_hash"], "reason": str(exc)},
                                    parents=[entry["entry_hash"]])
                except Exception:
                    pass
            if isinstance(exc, StoreRefused):
                raise
            raise StoreRefused(f"save refused and rolled back: {type(exc).__name__}: {exc}") from exc
        return {"data_sha256": digest, "entry": entry["entry_hash"], "score": scored}

    def audit(self, digest: str) -> dict:
        if not (isinstance(digest, str) and _KEY.fullmatch(digest)):
            raise StoreRefused("a digest is 64 hex characters")
        out = {}
        for label, b in self.backends.items():
            try:
                got = b.get(digest)
            except Exception:
                out[label] = "unavailable"
                continue
            out[label] = "missing" if got is None else (
                "ok" if hashlib.sha256(got).hexdigest() == digest else "corrupt")
        return out

    def load(self, digest: str) -> dict:
        """Return the capsule from the first source whose bytes verify. Raises if none does."""
        if not (isinstance(digest, str) and _KEY.fullmatch(digest)):
            raise StoreRefused("a digest is 64 hex characters")
        for b in self.backends.values():
            try:
                got = b.get(digest)
            except Exception:
                continue
            if got is not None and hashlib.sha256(got).hexdigest() == digest:
                return capsule_mod.from_bytes(got)
        raise StoreRefused("no source holds a verifying copy")
