"""RED TEAM PASS 1 (custody): attacks on the chain and on capsules. The attacker can edit files, feed garbage, race a second writer, or hide a secret in a value."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag import dag as dagmod
from vega_custody.dag.dag import Chain, ChainBroken, RecordRefused

FAKE_KEY = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3"          # credential-SHAPED, not a real key


def mk(n=5):
    t = pathlib.Path(tempfile.mkdtemp())
    paths = [t / "a.jsonl", t / "b.jsonl"]
    ch = Chain(paths)
    for i in range(n):
        ch.record("E", {"i": i})
    return t, paths, ch


class ChainAttacks(unittest.TestCase):
    def test_tail_truncation_is_caught_only_against_a_head_kept_elsewhere(self):
        """Attack: cut the newest entries from every replica. What remains is a VALID chain, so only a remembered head or length can expose it."""
        t, paths, ch = mk(5)
        head, n = ch.head(), len(ch)
        for p in paths:
            lines = p.read_bytes().splitlines(keepends=True)
            p.write_bytes(b"".join(lines[:3]))
        again = Chain(paths)                                   # opens fine: that is the weakness being shown
        self.assertTrue(again.verify()[0])
        ok, problems = again.verify(expected_head=head)
        self.assertFalse(ok)
        self.assertIn("truncated", " ".join(problems))
        self.assertFalse(again.verify(min_length=n)[0])

    def test_editing_a_middle_entry_is_detected_on_open_and_on_verify(self):
        t, paths, ch = mk(4)
        for p in paths:
            rows = [json.loads(x) for x in p.read_text().splitlines()]
            rows[1]["payload"]["i"] = 999
            p.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")
        with self.assertRaises(ChainBroken):
            Chain(paths)

    def test_a_non_object_row_is_a_clean_refusal_not_a_crash(self):
        t, paths, ch = mk(2)
        for p in paths:
            with open(p, "a") as f:
                f.write("[1,2]\n")
        with self.assertRaises(ChainBroken):
            Chain(paths)

    def test_one_replica_that_differs_is_refused(self):
        t, paths, ch = mk(3)
        with open(paths[1], "ab") as f:
            f.write(b"\n")
        with self.assertRaises(ChainBroken):
            Chain(paths)

    def test_nan_and_infinity_are_not_canonical_json(self):
        t, paths, ch = mk(1)
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(RecordRefused):
                ch.record("X", {"v": bad})

    def test_a_credential_shaped_value_is_refused_not_only_forbidden_key_names(self):
        t, paths, ch = mk(1)
        with self.assertRaises(RecordRefused):
            ch.record("X", {"note": "see " + FAKE_KEY})
        with self.assertRaises(RecordRefused):
            ch.record("X", {"list": [{"deep": FAKE_KEY}]})
        with self.assertRaises(RecordRefused):
            ch.record("X", {"items": [{"password": "x"}]})       # forbidden key inside a list of dicts
        self.assertTrue(ch.verify()[0])

    def test_a_second_writer_on_stale_state_is_refused_and_nothing_is_corrupted(self):
        t, paths, ch = mk(2)
        other = Chain(paths)
        ch.record("E", {"i": 100})
        with self.assertRaises(RecordRefused):
            other.record("E", {"i": 200})
        self.assertTrue(Chain(paths).verify()[0])

    def test_two_processes_appending_at_once_never_corrupt_the_chain(self):
        t, paths, ch = mk(1)
        worker = ("import sys, pathlib\nfrom vega_custody.dag.dag import Chain, ChainBroken, RecordRefused\n"
                  "paths=[pathlib.Path(p) for p in sys.argv[2:4]]; wid=sys.argv[1]; done=0; tries=0\n"
                  "while done<15 and tries<4000:\n    tries+=1\n    try:\n        Chain(paths).record('W',{'w':wid,'n':done}); done+=1\n    except (RecordRefused, ChainBroken):\n        pass\n"
                  "print(done)")
        env = dict(os.environ)
        procs = [subprocess.Popen([sys.executable, "-W", "ignore", "-c", worker, w, str(paths[0]), str(paths[1])], env=env, stdout=subprocess.PIPE, text=True) for w in ("A", "B")]
        counts = [int(p.communicate(timeout=300)[0].strip() or 0) for p in procs]
        again = Chain(paths)
        self.assertTrue(again.verify()[0], again.verify()[1])
        self.assertEqual(len(again), 1 + sum(counts))


class CapsuleAttacks(unittest.TestCase):
    def test_garbage_is_always_a_capsule_error_never_another_exception(self):
        good = cap.make("hello", {"source": "u"})
        cases = [None, [], 7, "text", {}, dict(good, data_b64="!!!notbase64!!!"), dict(good, data_type="evil"), dict(good, epoch=float("nan")),
                 dict(good, version="X"), {k: v for k, v in good.items() if k != "prefix_hash"}]
        for bad in cases:
            with self.assertRaises(cap.CapsuleError, msg=repr(bad)[:60]):
                cap.verify(bad)

    def test_text_capsule_whose_bytes_are_not_utf8_is_refused(self):
        import base64, hashlib
        c = cap.make("x", {"source": "u"})
        raw = b"\xff\xfe\xfa"
        c["data_b64"] = base64.b64encode(raw).decode()
        c["data_sha256"] = hashlib.sha256(raw).hexdigest()
        c["prefix_hash"] = cap._prefix_hash(c)                  # attacker re-seals it consistently
        with self.assertRaises(cap.CapsuleError):
            cap.verify(c)

    def test_altered_data_and_reordered_chain_are_detected(self):
        a = cap.make("one", {"source": "u"})
        b = cap.make("two", {"source": "u"}, predecessor=a["prefix_hash"])
        self.assertTrue(cap.verify_chain([a, b]))
        with self.assertRaises(cap.CapsuleError):
            cap.verify_chain([b, a])
        forged = dict(a, data_b64=cap.make("evil", {"source": "u"})["data_b64"])
        with self.assertRaises(cap.CapsuleError):
            cap.verify(forged)

    def test_metadata_cannot_smuggle_key_material_by_name_or_value(self):
        for md in ({"key": "x"}, {"nested": [{"Api_Key": "x"}]}, {"note": FAKE_KEY}):
            with self.assertRaises(cap.CapsuleError):
                cap.make("d", md)


if __name__ == "__main__":
    unittest.main()
