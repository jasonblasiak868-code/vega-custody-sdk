"""Selftest: exit 0 only if every check passes."""
import copy
import os
import sys

from vega_custody.capsule import capsule as cap  # noqa: E402

fails = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def refuses(fn):
    try:
        fn()
    except cap.CapsuleError:
        return True
    return False


a = cap.make("hello é中", {"source": "user"}, timestamp=1.0)
b = cap.make(b"\x00\x01binary", {"source": "model"}, predecessor=a["prefix_hash"], timestamp=2.0)
check("genuine capsule verifies", cap.verify(a) and cap.verify(b))
check("text roundtrips incl. unicode", cap.data_of(a) == "hello é中")
check("bytes roundtrip", cap.data_of(b) == b"\x00\x01binary")
check("chain verifies", cap.verify_chain([a, b]))
check("serialize roundtrip", cap.from_bytes(cap.to_bytes(b)) == b)

t = copy.deepcopy(a)
t["metadata"]["source"] = "attacker"
check("metadata edit caught", refuses(lambda: cap.verify(t)))
t = copy.deepcopy(a)
t["data_b64"] = cap.make("other")["data_b64"]
check("data swap caught", refuses(lambda: cap.verify(t)))
t = copy.deepcopy(a)
t["epoch"] = 99.0
check("timestamp edit caught", refuses(lambda: cap.verify(t)))
check("reordered chain caught", refuses(lambda: cap.verify_chain([b, a])))
check("dropped predecessor caught", refuses(lambda: cap.verify_chain([b])))
check("key material in metadata refused", refuses(lambda: cap.make("x", {"nested": {"passphrase": "p"}})))
check("non-str/bytes data refused", refuses(lambda: cap.make(123)))

print(f"{12 - len(fails)}/12 passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
