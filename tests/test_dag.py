"""Selftest: exit 0 only if every check passes."""
import os
import pathlib
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from vega_custody.dag.dag import ChainBroken, Dag, RecordRefused  # noqa: E402

fails = []
N = 0


def check(name, cond):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


tmp = pathlib.Path(tempfile.mkdtemp())
cp = [tmp / "a" / "content.jsonl", tmp / "b" / "content.jsonl"]
lp = [tmp / "a" / "loc.jsonl", tmp / "b" / "loc.jsonl"]
d = Dag(cp, lp)

e0 = d.record("GENESIS", {"note": "start"})
e1 = d.record("ACTION", {"data_sha256": "ab" * 32})
e2 = d.record("ACTION", {"x": 1}, parents=[e0["entry_hash"]])
m = d.record("MERGE", {"x": 2}, parents=[e1["entry_hash"], e2["entry_hash"]])
check("multi-parent DAG entry accepted", len(m["parents"]) == 2)
check("chain verifies", d.verify()[0])
check("replicas byte-identical", cp[0].read_bytes() == cp[1].read_bytes())

big = "x" * 2_000_000
eb = d.record("BIG", {"data_sha256": "cd" * 32, "blob": big})
check("no truncation: 2 MB payload stored whole", d.content.get(eb["entry_hash"])["payload"]["blob"] == big)

check("unknown parent refused", raises(RecordRefused, lambda: d.record("X", {}, parents=["f" * 64])))
check("key material refused", raises(RecordRefused, lambda: d.record("X", {"a": {"private_key": "p"}})))
check("non-JSON payload refused", raises(RecordRefused, lambda: d.record("X", {"a": b"bytes"})))

loc = d.record_location(e1["entry_hash"], "local", "file:///x", "ab" * 32)
check("location recorded against content entry", d.locations.where(e1["entry_hash"])[0]["entry_hash"] == loc["entry_hash"])
check("location with wrong read-back refused",
      raises(RecordRefused, lambda: d.record_location(e1["entry_hash"], "server", "u", "00" * 32)))
check("location for unknown content refused",
      raises(RecordRefused, lambda: d.record_location("e" * 64, "local", "u", "ab" * 32)))
check("bad location class refused",
      raises(RecordRefused, lambda: d.record_location(e1["entry_hash"], "usb", "u", "ab" * 32)))
check("stage records digest only",
      d.record_stage("aes-gcm", "12" * 32)["kind"] == "STAGE:aes-gcm"
      and raises(RecordRefused, lambda: d.record_stage("aes-gcm", "not a digest")))

# record-or-refuse: after opening, make one replica unwritable (a directory where its ledger file should be)
r1, r2 = tmp / "d" / "content.jsonl", tmp / "e" / "content.jsonl"
d2 = Dag([r1, r2], [tmp / "d" / "loc.jsonl"])
d2.record("OK", {"a": 0})
size_before = r1.stat().st_size
r2.unlink()
r2.mkdir()
check("unwritable replica refuses the record", raises(RecordRefused, lambda: d2.record("X", {"a": 1})))
check("primary rolled back to its prior size", r1.stat().st_size == size_before)
check("unreadable ledger refuses to open", raises(ChainBroken, lambda: Dag([r1, r2], [tmp / "d" / "loc.jsonl"])))

# a second writer over the same files must not be able to fork the chain
stale = Dag(cp, lp)
d.record("ADVANCE", {"n": 1})
check("stale second writer refused", raises(RecordRefused, lambda: stale.record("FORK", {"n": 2})))
check("chain still verifies after refused fork", d.verify()[0])

# tamper: edit one replica, independent verify must flag it and a reopen must refuse
raw = cp[1].read_bytes().replace(b'"note": "start"', b'"note": "EVIL!"')
cp[1].write_bytes(raw)
check("tampered replica detected by verify", not d.verify()[0])
check("tampered ledger refuses to reopen", raises(ChainBroken, lambda: Dag(cp, lp)))

print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
