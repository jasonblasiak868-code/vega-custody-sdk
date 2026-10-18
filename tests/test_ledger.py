"""Selftest: exit 0 only if every check passes."""
import os
import pathlib
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from vega_custody.ledger import merkle  # noqa: E402
from vega_custody.ledger.backend_drive import DriveBackend  # noqa: E402
from vega_custody.ledger.backend_local import LocalBackend  # noqa: E402
from vega_custody.ledger.backend_timestamp import FileWitness, Witness  # noqa: E402
from vega_custody.ledger.ledger import Ledger, LedgerRefused, LedgerUnavailable  # noqa: E402

fails, N = [], 0


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


def com(i):
    return {"kind": "WCOMMIT", "device": "dev", "surface": "s", "action": "spend_funds",
            "action_hash": f"{i:064x}", "expiry": 2_000_000_000 + i, "nonce_sha256": f"{i + 1000:064x}"}


t = pathlib.Path(tempfile.mkdtemp())
local, drive = LocalBackend(t / "local" / "l.jsonl"), DriveBackend(t / "usb" / "l.jsonl", mount_point=t, verify_mount=False)
L = Ledger([local, drive])
r = L.mint(com(1))
check("mint writes to both replicas", r["replicas"] == 2 and (t / "local" / "l.jsonl").read_bytes() == (t / "usb" / "l.jsonl").read_bytes())
check("verify true for minted commitment", L.verify(com(1)))
check("verify false for unminted commitment", not L.verify(com(2)))
check("verify false for altered commitment", not L.verify({**com(1), "action": "grant_authority"}))
check("duplicate mint refused (single use)", raises(LedgerRefused, lambda: L.mint(com(1))))
check("parameters cannot ride in the commitment", raises(LedgerRefused, lambda: L.mint({**com(3), "params": {"to": "x"}})))
check("missing field refused", raises(LedgerRefused, lambda: L.mint({"action": "x"})))

# required drive missing: refuse to run; optional drive missing: runs, flagged degraded
gone = DriveBackend(t / "nodrive" / "x" / "l.jsonl", mount_point=t / "nodrive", verify_mount=False)
check("required missing drive refuses", raises(LedgerUnavailable, lambda: Ledger([local, gone])))
gone_opt = DriveBackend(t / "nodrive" / "x" / "l.jsonl", mount_point=t / "nodrive", required=False, verify_mount=False)
L2 = Ledger([LocalBackend(t / "l2" / "l.jsonl"), gone_opt])
check("optional missing drive marks degraded", L2.mint(com(9))["degraded"] == ["drive"])

# tamper with the drive copy: verify must go False and a reopen must refuse
p = t / "usb" / "l.jsonl"
p.write_bytes(p.read_bytes().replace(b'"spend_funds"', b'"spend_funxx"'))
check("tampered replica makes verify fail closed", not L.verify(com(1)))
check("tampered ledger refuses to reopen", raises(LedgerUnavailable, lambda: Ledger([local, drive])))

# merkle: every leaf of odd and even batches proves against the root, a wrong leaf does not
for n in (1, 2, 3, 5, 8):
    leaves = [bytes([i]) * 32 for i in range(n)]
    rt = merkle.root(leaves)
    check(f"merkle n={n} all proofs verify", all(merkle.verify_proof(leaves[i], merkle.proof(leaves, i), rt) for i in range(n)))
check("merkle wrong leaf fails", not merkle.verify_proof(b"x" * 32, merkle.proof([b"a" * 32, b"b" * 32], 0), merkle.root([b"a" * 32, b"b" * 32])))


class Boom(Witness):
    def anchor(self, root_hex):
        raise ConnectionError("offline")


# batching + anchoring
t2 = pathlib.Path(tempfile.mkdtemp())
W = FileWitness(t2 / "roots.jsonl")
L3 = Ledger([LocalBackend(t2 / "l.jsonl")], witness=W, batch_size=3)
rs = [L3.mint(com(i)) for i in range(10, 13)]
check("batch of 3 anchors one root", "anchor" in rs[-1] and rs[-1]["anchor"]["count"] == 3)
ip = L3.inclusion_proof(com(11))
check("inclusion proof verifies against anchored root",
      ip and merkle.verify_proof(bytes.fromhex(ip["leaf"]), ip["path"], bytes.fromhex(ip["root"]))
      and ip["root"] == rs[-1]["anchor"]["root"])
check("witness file got a root only", len((t2 / "roots.jsonl").read_text().splitlines()) == 1
      and "action" not in (t2 / "roots.jsonl").read_text())

L4 = Ledger([LocalBackend(t2 / "l4.jsonl")], witness=Boom(), batch_size=1)
rr = L4.mint(com(50))
check("witness failure never loses the mint", "anchor_error" in rr and L4.verify(com(50)))

print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
