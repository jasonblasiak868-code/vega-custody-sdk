"""dag.py - append-only hash-linked record of what happened (content DAG) and where it lives (location DAG).

Rules enforced here, in code, not by convention:
  - RECORD-OR-REFUSE: an entry is written to every ledger replica and read back before the call returns. Any
    failure rolls the partial writes back and raises. An unrecorded action is unreachable, not just detectable.
  - NO TRUNCATION: nothing written here is length-limited.
  - HASHES ONLY: payloads may not carry key material (a payload with a secret-looking field name is refused).
  - FAIL CLOSED: a ledger that is broken, or whose replicas disagree, refuses to be extended.
  - A true DAG: an entry may name several parents; every parent must already exist.
"""
import datetime
import hashlib
import json
import os
import re
import pathlib
import threading
import time

ZERO = "0" * 64
FORBIDDEN_FIELDS = frozenset({"key", "secret", "passphrase", "password", "private_key", "privkey",
                              "token", "seed", "api_key"})


class DagError(Exception):
    pass


class ChainBroken(DagError):
    pass


class RecordRefused(DagError):
    pass


FORBIDDEN_NORMALIZED = frozenset({"key", "secret", "passphrase", "password", "privatekey", "privkey", "token", "seed", "apikey", "accesstoken", "refreshtoken", "secretkey", "authorization", "bearer",
                                  "credential", "credentials", "clientsecret", "sessiontoken", "authtoken"})


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _field_names(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _field_names(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _field_names(v)


_SECRET_VALUE = re.compile(
    r"sk-[A-Za-z0-9_\-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|nvapi-[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_\-]{16,}|hf_[A-Za-z0-9]{30,}"
    r"|npm_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,}|ya29\.[A-Za-z0-9_\-]{20,}"
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|(?i:bearer)\s+[A-Za-z0-9._~+/\-]{24,}=*"
    r"|(?i:api[_-]?key|secret|passw(?:or)?d|token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+_\-]{20,}"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY(?: BLOCK)?-----")


def _secret_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _secret_values(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _secret_values(v)
    elif isinstance(obj, str) and _SECRET_VALUE.search(obj):
        yield obj


def contains_credential(value) -> bool:
    """True if any string inside value (text, list, dict) is credential-shaped. The same test the chain applies before it records anything."""
    return next(_secret_values(value), None) is not None


def _entry_hash(entry: dict) -> str:
    return sha256_hex(canonical({k: v for k, v in entry.items() if k != "entry_hash"}))


class _FileLock:
    """Cross-process exclusive lock on <primary>.lock around check-and-append, so two processes cannot interleave. A second writer is refused or waits; it never corrupts."""

    def __init__(self, path):
        self.lp = str(path) + ".lock"
        self.fd = None

    def __enter__(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.lp)), exist_ok=True)
        self.fd = os.open(self.lp, os.O_CREAT | os.O_RDWR)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError as exc:
            os.close(self.fd)
            raise RecordRefused(f"could not take the ledger lock: {exc}") from exc
        return self

    def __exit__(self, *a):
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self.fd, 0, 0)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)


class Chain:
    """One append-only ledger, written identically to every path in `paths` (paths[0] is the primary)."""

    def __init__(self, paths):
        self.paths = [pathlib.Path(p) for p in paths]
        if not self.paths:
            raise DagError("a chain needs at least one ledger path")
        self._lock = threading.Lock()
        self._rows = []
        self._index = {}
        self._load()

    def _read(self, path):
        if not path.exists():
            return b"", []
        raw = path.read_bytes()
        return raw, [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]

    def _load(self):
        try:
            raws, parsed = zip(*[self._read(p) for p in self.paths])
        except (OSError, ValueError) as exc:
            raise ChainBroken(f"ledger unreadable, refusing to open: {exc}") from exc
        if any(r != raws[0] for r in raws):
            raise ChainBroken("ledger replicas disagree; refusing to open. Repair or resync from a verified copy.")
        problems = self._check(parsed[0])
        if problems:
            raise ChainBroken("; ".join(problems))
        self._rows = list(parsed[0])
        self._index = {r["entry_hash"]: i for i, r in enumerate(self._rows)}
        self._sizes = {p: len(raws[0]) for p in self.paths}

    @staticmethod
    def _check(rows):
        problems, seen = [], set()
        for i, r in enumerate(rows):
            if not isinstance(r, dict):
                problems.append(f"entry {i}: not a JSON object")
                continue
            if r.get("seq") != i:
                problems.append(f"entry {i}: bad seq")
            if _entry_hash(r) != r.get("entry_hash"):
                problems.append(f"entry {i}: hash mismatch (edited)")
            parents = r.get("parents", [])
            if i > 0 and not parents:
                problems.append(f"entry {i}: no parent")
            for p in parents:
                if p not in seen:
                    problems.append(f"entry {i}: unknown parent")
            seen.add(r.get("entry_hash"))
        return problems

    # ------------------------------------------------------------------ reads
    def __len__(self):
        return len(self._rows)

    def head(self):
        return self._rows[-1]["entry_hash"] if self._rows else None

    def has(self, entry_hash) -> bool:
        return entry_hash in self._index

    def get(self, entry_hash):
        i = self._index.get(entry_hash)
        return None if i is None else self._rows[i]

    def entries(self):
        return list(self._rows)

    def read_primary(self):
        """Entries as they are on disk right now (primary ledger), not as held in memory."""
        return self._read(self.paths[0])[1]

    def verify(self, expected_head=None, min_length=None):
        """Re-read every replica off disk. Returns (ok, problems). Trusts nothing held in memory.
        expected_head / min_length: the head hash and length remembered ELSEWHERE (an anchor, a receipt). A chain alone cannot show that its newest entries
        were cut off, because what remains is still a valid chain; only a head you kept outside the chain can."""
        problems = []
        raws, parsed = [], []
        for p in self.paths:
            try:
                raw, rows = self._read(p)
            except (OSError, ValueError) as exc:
                problems.append(f"{p}: unreadable ({exc})")
                continue
            raws.append(raw)
            parsed.append(rows)
            problems += [f"{p}: {x}" for x in self._check(rows)]
        if any(r != raws[0] for r in raws):
            problems.append("replicas disagree")
        if parsed and expected_head is not None and not any(isinstance(r, dict) and r.get("entry_hash") == expected_head for r in parsed[0]):
            problems.append("expected head is not in the chain: it was truncated or replaced")
        if parsed and min_length is not None and len(parsed[0]) < min_length:
            problems.append(f"chain has {len(parsed[0])} entries, expected at least {min_length}: truncated")
        return (not problems), problems

    # ----------------------------------------------------------------- writes
    def record(self, kind: str, payload: dict, parents=None) -> dict:
        if not isinstance(kind, str) or not kind:
            raise RecordRefused("kind required")
        if not isinstance(payload, dict):
            raise RecordRefused("payload must be a JSON object")
        bad = {n for n in _field_names(payload) if re.sub(r"[^a-z0-9]", "", n.lower()) in FORBIDDEN_NORMALIZED}
        if bad:
            raise RecordRefused(f"payload carries forbidden field(s) {sorted(bad)}: chains hold hashes only")
        try:
            canonical(payload)
        except (TypeError, ValueError) as exc:
            raise RecordRefused(f"payload is not canonical JSON: {exc}")
        if next(_secret_values(payload), None) is not None:
            raise RecordRefused("payload carries a credential-shaped value: chains hold hashes only")
        with self._lock:
            if parents is None:
                parents = [self.head()] if self._rows else []
            parents = list(parents)
            if self._rows and not parents:
                raise RecordRefused("non-genesis entry needs at least one parent")
            for p in parents:
                if p not in self._index:
                    raise RecordRefused("unknown parent")
            now = time.time()
            entry = {"seq": len(self._rows), "kind": kind, "payload": payload, "parents": parents,
                     "epoch": now,
                     "utc": datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()}
            entry["entry_hash"] = _entry_hash(entry)
            self._append_everywhere(entry)
            self._rows.append(entry)
            self._index[entry["entry_hash"]] = entry["seq"]
            return entry

    def _append_everywhere(self, entry):
        with _FileLock(self.paths[0]):
            self._append_locked(entry)

    def _append_locked(self, entry):
        line = (json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        sizes = {p: (p.stat().st_size if p.exists() else 0) for p in self.paths}
        if sizes != self._sizes:
            raise RecordRefused("ledger changed underneath this writer (another writer?); reopen it. Nothing appended.")
        touched = []
        try:
            for p in list(reversed(self.paths)):  # replicas first, primary last
                p.parent.mkdir(parents=True, exist_ok=True)
                touched.append(p)
                with open(p, "ab") as fh:
                    fh.write(line)
                    fh.flush()
                with open(p, "rb") as fh:
                    fh.seek(sizes[p])
                    if fh.read() != line:
                        raise OSError(f"read-back mismatch at {p}")
            self._sizes = {p: sizes[p] + len(line) for p in self.paths}
        except Exception as exc:
            rollback_failed = []
            for p in touched:
                try:
                    with open(p, "r+b") as fh:
                        fh.truncate(sizes[p])
                except OSError:
                    rollback_failed.append(str(p))
            more = f"; ROLLBACK FAILED on {rollback_failed}: replicas may now disagree, reopen and repair" if rollback_failed else ""
            raise RecordRefused(f"record refused, nothing appended: {type(exc).__name__}: {exc}{more}") from exc


class Dag:
    """The two chains an action must land in: what happened (content) and where it is stored (locations)."""

    def __init__(self, content_paths, location_paths):
        from vega_custody.dag.locations import LocationChain
        self.content = Chain(content_paths)
        self.locations = LocationChain(location_paths, self.content)

    def record(self, kind, payload, parents=None):
        return self.content.record(kind, payload, parents)

    def record_location(self, content_entry_hash, location_class, uri, readback_sha256, **extra):
        return self.locations.record_location(content_entry_hash, location_class, uri, readback_sha256, **extra)

    def record_stage(self, stage: str, digest: str, parents=None, **extra):
        """One layer of the superproof pipeline (capsule, aes-gcm, chacha20, a tier-1/2/3 proof ...). Digest only."""
        if not (isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)):
            raise RecordRefused("a stage records a sha256 hex digest, never the data itself")
        return self.content.record("STAGE:" + stage, {"stage": stage, "digest": digest, **extra}, parents)

    def verify(self):
        ok1, p1 = self.content.verify()
        ok2, p2 = self.locations.verify()
        return (ok1 and ok2), p1 + p2
