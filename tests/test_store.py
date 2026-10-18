"""Selftest: exit 0 only if every check passes."""
import os
import pathlib
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from vega_custody.capsule import capsule as cap  # noqa: E402
from vega_custody.dag.dag import Dag  # noqa: E402
from vega_custody.store.store import DirBackend, StoreRefused, ThreeSourceStore  # noqa: E402

fails = []
N = 0


def check(name, cond):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def refused(fn):
    try:
        fn()
    except StoreRefused:
        return True
    return False


class Corrupting(DirBackend):
    def put(self, key, data):
        super().put(key, data + b"!")


class Down(DirBackend):
    def get(self, key):
        raise ConnectionError("server unreachable")

    def put(self, key, data):
        raise ConnectionError("server unreachable")


def fresh(server_cls=DirBackend):
    t = pathlib.Path(tempfile.mkdtemp())
    d = Dag([t / "dag" / "c.jsonl"], [t / "dag" / "l.jsonl"])
    b = {"local": DirBackend(t / "local"), "external": DirBackend(t / "ext"), "server": server_cls(t / "srv")}
    return t, d, b, ThreeSourceStore(b, d)


meta = {"source": "user", "license_class": "own"}
t, d, b, s = fresh()
c = cap.make("first turn", meta)
r = s.save(c)
check("save lands on all three sources", all(v == "ok" for v in s.audit(r["data_sha256"]).values()))
check("save is scored", 0.0 <= r["score"]["score"] <= 1.0 and r["score"]["scorer"])
check("content DAG has the save", d.content.has(r["entry"]))
check("location DAG has one entry per source", len(d.locations.where(r["entry"])) == 3)
check("DAGs verify", d.verify()[0])
check("load returns the capsule", s.load(r["data_sha256"]) == c)

c2 = cap.make("second turn", meta, predecessor=c["prefix_hash"])
r2 = s.save(c2)
check("lineage preserved in the DAG", d.content.get(r2["entry"])["payload"]["predecessor"] == c["prefix_hash"])

altered = dict(c2)
altered["metadata"] = {"source": "attacker"}
check("altered capsule refused", refused(lambda: s.save(altered)))

# one source corrupts on write: refuse, and nothing may remain on the other two
t, d, b, s = fresh(Corrupting)
c = cap.make("will not land", meta)
dig = __import__("hashlib").sha256(cap.to_bytes(c)).hexdigest()
check("read-back mismatch refuses the save", refused(lambda: s.save(c)))
check("rolled back: no copy left anywhere",
      b["local"].get(dig) is None and b["external"].get(dig) is None)
check("refusal recorded in DAG (nothing saved)", not any(r["kind"] == "SAVE" for r in d.content.entries()))

# one source down: fail closed
t, d, b, s = fresh(Down)
check("unavailable source refuses the save", refused(lambda: s.save(cap.make("x", meta))))

# tampered stored copy is detected on audit
t, d, b, s = fresh()
r = s.save(cap.make("audit me", meta))
pathlib.Path(b["external"].uri(r["data_sha256"])).write_bytes(b"garbage")
check("audit flags the corrupt copy", s.audit(r["data_sha256"])["external"] == "corrupt")
check("load still returns a verifying copy", s.load(r["data_sha256"])["data_sha256"])

# a scorer that returns nothing cannot save
t, d, b, _ = fresh()
s_noscore = ThreeSourceStore(b, d, scorer=lambda c: None)
check("unscored save refused", refused(lambda: s_noscore.save(cap.make("y", meta))))
check("below-minimum score refused",
      refused(lambda: ThreeSourceStore(b, d, min_score=1.0).save(cap.make("z", {}))))
check("all three sources required",
      refused(lambda: ThreeSourceStore({"local": b["local"]}, d)))

print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
