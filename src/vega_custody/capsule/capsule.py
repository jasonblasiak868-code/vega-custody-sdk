"""capsule.py - every prompt, action and response is wrapped in a turn capsule before it goes anywhere.

A capsule carries: the data, its metadata, a timestamp, the hash of its predecessor, and its own prefix hash
(a digest over everything that precedes it in the capsule). Altering any field, or reordering a sequence,
changes a hash and is caught by verify()/verify_chain(). The hash is proof, not secrecy: encryption is a
separate layer (seal)."""
import base64
import datetime
import hashlib
import json
import re
import time

VERSION = "VEGA-CAPSULE-1"
GENESIS = "0" * 64
FORBIDDEN_FIELDS = frozenset({"key", "secret", "passphrase", "password", "private_key", "privkey",
                              "token", "seed", "api_key"})


class CapsuleError(Exception):
    pass


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _names(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k).lower()
            yield from _names(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _names(v)


_SECRET_VALUE = re.compile(r"sk-[A-Za-z0-9_\-]{20,}|nvapi-[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")


def _has_secret_value(obj) -> bool:
    if isinstance(obj, dict):
        return any(_has_secret_value(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_secret_value(v) for v in obj)
    return isinstance(obj, str) and bool(_SECRET_VALUE.search(obj))


def _prefix_hash(c: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in c.items() if k != "prefix_hash"})).hexdigest()


def make(data, metadata=None, predecessor=None, timestamp=None) -> dict:
    """Seal one turn. `data` is bytes or str. `predecessor` is the previous capsule's prefix_hash (None = first)."""
    if metadata is not None and not isinstance(metadata, dict):
        raise CapsuleError("metadata must be a dict")
    metadata = dict(metadata or {})
    if FORBIDDEN_FIELDS.intersection(_names(metadata)):
        raise CapsuleError("metadata may not carry key material")
    if _has_secret_value(metadata):
        raise CapsuleError("metadata carries a credential-shaped value")
    try:
        _canonical(metadata)
    except (TypeError, ValueError) as exc:
        raise CapsuleError(f"metadata is not canonical JSON: {exc}") from exc
    if isinstance(data, str):
        raw, kind = data.encode("utf-8"), "text"
    elif isinstance(data, (bytes, bytearray)):
        raw, kind = bytes(data), "bytes"
    else:
        raise CapsuleError("data must be str or bytes")
    try:
        now = time.time() if timestamp is None else float(timestamp)
        datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise CapsuleError("timestamp is not a usable time") from exc
    c = {
        "version": VERSION,
        "data_type": kind,
        "data_b64": base64.b64encode(raw).decode("ascii"),
        "data_sha256": hashlib.sha256(raw).hexdigest(),
        "metadata": metadata,
        "epoch": now,
        "utc": datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat(),
        "predecessor": predecessor or GENESIS,
    }
    c["prefix_hash"] = _prefix_hash(c)
    return c


def data_of(c: dict):
    raw = base64.b64decode(c["data_b64"])
    return raw.decode("utf-8") if c["data_type"] == "text" else raw


def verify(c: dict) -> bool:
    """Raises CapsuleError on any inconsistency; returns True otherwise."""
    if not isinstance(c, dict):
        raise CapsuleError("a capsule is a JSON object")
    for f in ("version", "data_type", "data_b64", "data_sha256", "metadata", "epoch", "utc", "predecessor",
              "prefix_hash"):
        if f not in c:
            raise CapsuleError(f"missing field {f}")
    if c["version"] != VERSION:
        raise CapsuleError("unknown capsule version")
    if not isinstance(c["metadata"], dict):
        raise CapsuleError("capsule metadata must be an object")
    if c["data_type"] not in ("text", "bytes"):
        raise CapsuleError("data_type must be text or bytes")
    try:
        raw = base64.b64decode(c["data_b64"], validate=True)
        if c["data_type"] == "text":
            raw.decode("utf-8")
        got = _prefix_hash(c)
    except (ValueError, TypeError) as exc:   # bad base64, bad utf-8, or non-canonical JSON (NaN)
        raise CapsuleError(f"capsule fields are malformed: {type(exc).__name__}") from exc
    if hashlib.sha256(raw).hexdigest() != c["data_sha256"]:
        raise CapsuleError("data does not match its digest")
    if got != c["prefix_hash"]:
        raise CapsuleError("prefix hash mismatch: capsule was altered")
    return True


def verify_chain(capsules) -> bool:
    prev = GENESIS
    for i, c in enumerate(capsules):
        verify(c)
        if c["predecessor"] != prev:
            raise CapsuleError(f"capsule {i}: predecessor does not match the previous capsule")
        prev = c["prefix_hash"]
    return True


def to_bytes(c: dict) -> bytes:
    return _canonical(c)


def from_bytes(b: bytes) -> dict:
    c = json.loads(b.decode("utf-8"))
    verify(c)
    return c
