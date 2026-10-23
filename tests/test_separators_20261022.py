"""Regression tests (2026-10-22): the writer stores text as UTF-8 with ensure_ascii=False, so U+2028, U+2029 and U+0085 land in the file raw. The reader used str.splitlines(),
which also splits at those characters, so a chain holding one of them could not be reopened (ChainBroken). An entry is separated by a real newline only."""
import pathlib
import tempfile
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag import dag as d


class ReopenWithUnusualCharacters(unittest.TestCase):
    def test_a_chain_holding_line_separator_characters_reopens_and_verifies(self):
        for ch in (" ", " ", "\x85", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "﻿"):
            p = pathlib.Path(tempfile.mkdtemp()) / "c.jsonl"
            first = d.Chain([str(p)])
            e = first.record("T", {"text": "a" + ch + "b"})
            again = d.Chain([str(p)])                          # must not raise
            self.assertEqual(len(again), 1, repr(ch))
            self.assertEqual(again.head(), e["entry_hash"], repr(ch))
            ok, problems = again.verify()
            self.assertTrue(ok, (repr(ch), problems))
            again.record("T2", {"text": "after"})              # and it can be extended
            self.assertEqual(len(d.Chain([str(p)])), 2)


class CapsuleInputs(unittest.TestCase):
    def test_bad_metadata_or_time_is_a_capsule_error(self):
        for bad in ("notadict", ["a"], 5):
            with self.assertRaises(cap.CapsuleError, msg=repr(bad)):
                cap.make("x", bad)
        for ts in (float("nan"), float("inf"), "abc", 10 ** 30):
            with self.assertRaises(cap.CapsuleError, msg=repr(ts)):
                cap.make("x", {}, timestamp=ts)
        self.assertTrue(cap.make("x", {"ok": 1}, timestamp=1760985600.0)["prefix_hash"])


if __name__ == "__main__":
    unittest.main()
