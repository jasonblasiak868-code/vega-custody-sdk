"""RED TEAM PASS 2 (custody): attacks on authority (who can mint), on proofs, on the drive and on the store."""
import hashlib
import json
import os
import pathlib
import tempfile
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger import merkle
from vega_custody.ledger.backend_drive import DriveBackend
from vega_custody.ledger.backend_local import BackendUnavailable, LocalBackend
from vega_custody.ledger.ledger import Ledger, LedgerRefused
from vega_custody.store.store import DirBackend, StoreRefused, ThreeSourceStore


def commitment(n=1):
    return {"kind": "WCOMMIT", "device": "d", "surface": "s", "action": "a", "action_hash": f"{n:064x}", "expiry": 9999999999, "nonce_sha256": f"{n + 7:064x}"}


class LedgerAttacks(unittest.TestCase):
    def setUp(self):
        self.t = pathlib.Path(tempfile.mkdtemp())
        self.led = Ledger([LocalBackend(self.t / "led.jsonl")])

    def test_the_read_only_view_cannot_mint_or_be_extended(self):
        """Attack: code that is only supposed to CHECK commitments fabricates one. Hand gates led.reader(), keep mint for the commit step."""
        c = commitment(1)
        r = self.led.reader()
        self.assertFalse(hasattr(r, "mint"))
        self.assertFalse(hasattr(r, "chain"))
        with self.assertRaises(AttributeError):
            r.mint = lambda x: x
        self.assertFalse(r.verify(c))
        self.led.mint(c)
        self.assertTrue(r.verify(c))

    def test_mint_is_single_use_and_metadata_only(self):
        self.led.mint(commitment(2))
        with self.assertRaises(LedgerRefused):
            self.led.mint(commitment(2))
        with self.assertRaises(LedgerRefused):
            self.led.mint(dict(commitment(3), parameters={"x": 1}))
        with self.assertRaises(LedgerRefused):
            self.led.mint({"action": "a"})

    def test_a_forged_or_changed_commitment_does_not_verify(self):
        c = commitment(4)
        self.led.mint(c)
        self.assertFalse(self.led.verify(dict(c, action="other")))
        self.assertFalse(self.led.verify(dict(c, expiry=1)))

    def test_editing_the_ledger_file_makes_everything_fail_closed(self):
        c = commitment(5)
        self.led.mint(c)
        p = self.t / "led.jsonl"
        rows = [json.loads(x) for x in p.read_text().splitlines()]
        rows[0]["payload"]["commitment"]["action"] = "tampered"
        p.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")
        self.assertFalse(self.led.verify(c))

    def test_merkle_proofs_reject_bad_sides_bad_roots_and_internal_nodes_posing_as_leaves(self):
        leaves = [hashlib.sha256(bytes([i])).digest() for i in range(5)]
        root = merkle.root(leaves)
        for i in range(5):
            self.assertTrue(merkle.verify_proof(leaves[i], merkle.proof(leaves, i), root))
        with self.assertRaises(ValueError):
            merkle.proof(leaves, 5)
        with self.assertRaises(ValueError):
            merkle.proof(leaves, -1)
        path = merkle.proof(leaves, 0)
        self.assertFalse(merkle.verify_proof(leaves[0], [("X", path[0][1])] + path[1:], root))
        self.assertFalse(merkle.verify_proof(leaves[0], [("L", b"short")] + path[1:], root))
        self.assertFalse(merkle.verify_proof(leaves[0], path, merkle.root(leaves[:4])))
        two = leaves[:2]
        inner = merkle._node(merkle._leaf(two[0]), merkle._leaf(two[1]))      # the internal node of a 2-leaf tree
        self.assertFalse(merkle.verify_proof(inner, [], merkle.root(two)), "second-preimage: an internal node must not pass as a leaf")


class DriveAttacks(unittest.TestCase):
    def test_a_plain_folder_is_not_a_mounted_drive(self):
        """Attack: the stick is unplugged but its mount-point folder still exists, so writes would land on the system disk."""
        t = pathlib.Path(tempfile.mkdtemp())
        d = DriveBackend(t / "usb" / "l.jsonl", mount_point=t)
        with self.assertRaises(BackendUnavailable):
            d.check()

    @unittest.skipIf(os.name == "nt", "root anchor '/' only exists on POSIX")
    def test_posix_root_anchor_is_never_accepted_as_a_mount(self):
        with self.assertRaises(BackendUnavailable):
            DriveBackend("/usb/l.jsonl")


class StoreAttacks(unittest.TestCase):
    def mk(self, same=None):
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        b = {"local": DirBackend(t / "a"), "external": DirBackend(t / "b"), "server": DirBackend(t / "c")}
        return t, dag, b

    def test_path_traversal_digests_are_refused_everywhere(self):
        t, dag, b = self.mk()
        st = ThreeSourceStore(b, dag)
        (t / "secret.txt").write_text("x")
        for bad in ("../secret.txt", "..\\..\\secret.txt", "a" * 63, "A" * 64, "", None, 5):
            with self.assertRaises(StoreRefused):
                st.load(bad)
            with self.assertRaises(StoreRefused):
                st.audit(bad)
        with self.assertRaises(StoreRefused):
            b["local"].get("../secret.txt")

    def test_three_sources_in_one_place_are_refused(self):
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        one = DirBackend(t / "same")
        with self.assertRaises(StoreRefused):
            ThreeSourceStore({"local": one, "external": DirBackend(t / "same"), "server": DirBackend(t / "x")}, dag)
        with self.assertRaises(StoreRefused):
            ThreeSourceStore({"local": DirBackend(t / "p"), "external": DirBackend(t / "p" / "inner"), "server": DirBackend(t / "q")}, dag)

    def test_a_corrupt_first_source_is_skipped_and_reported(self):
        t, dag, b = self.mk()
        st = ThreeSourceStore(b, dag)
        c = cap.make("payload", {"source": "u", "license_class": "x"})
        rec = st.save(c)
        digest = rec["data_sha256"]
        (t / "a" / digest).write_bytes(b"corrupted")
        self.assertEqual(st.audit(digest)["local"], "corrupt")
        self.assertEqual(st.load(digest)["prefix_hash"], c["prefix_hash"])

    def test_a_backend_that_fails_on_the_last_source_leaves_no_residue(self):
        t, dag, b = self.mk()

        class Failing(DirBackend):
            def put(self, key, data):
                raise OSError("disk full")
        b["server"] = Failing(t / "c")
        st = ThreeSourceStore(b, dag)
        with self.assertRaises(StoreRefused):
            st.save(cap.make("payload", {"source": "u"}))
        self.assertEqual([p.name for p in (t / "a").iterdir()], [])
        self.assertEqual([p.name for p in (t / "b").iterdir()], [])
        self.assertTrue(dag.verify()[0])

    def test_an_object_already_present_with_the_wrong_bytes_is_never_trusted(self):
        t, dag, b = self.mk()
        c = cap.make("payload", {"source": "u"})
        digest = hashlib.sha256(cap.to_bytes(c)).hexdigest()
        (t / "b" / digest).write_bytes(b"planted")
        with self.assertRaises(StoreRefused):
            ThreeSourceStore(b, dag).save(c)


if __name__ == "__main__":
    unittest.main()
