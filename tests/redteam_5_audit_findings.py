"""Regression tests for the security-audit pass over the custody repo (2026-10-17)."""
import pathlib
import tempfile
import unittest

from vega_custody import safepaths as sp
from vega_custody.dag.dag import Dag, RecordRefused, contains_credential


class C1_CredentialShapes(unittest.TestCase):
    """MEDIUM. The credential scan only knew a handful of key formats; common ones (Hugging Face, Stripe, JWT, npm, GitLab, bearer headers, key=value assignments) were recorded as ordinary text, and
    so were fields named api_key, accessToken or Authorization."""

    JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    SHAPES = ["hf_" + "a" * 34, "sk_live_" + "A1b2C3d4" * 3, JWT, "npm_" + "a1" * 20, "glpat-" + "x" * 20, "Authorization: Bearer " + "abcdef0123456789" * 2, 'pass' + 'word = "hunter2hunter2hunter2"',
              "api_key: abcdefghijklmnopqrstuvwxyz", "github_pat_" + "A" * 40, "ya29." + "b" * 30, "sk-" + "a1B2c3D4" * 4, "AKIA" + "ABCDEFGHIJKLMNOP"]
    PLAIN = ["the token budget is 500", "a secret garden", "password policy: rotate often", "hf_short", "tokens_est: 12", "keyboard", "bearer of news", "sk-short"]

    def test_every_common_credential_shape_is_found(self):
        for x in self.SHAPES:
            self.assertTrue(contains_credential(x), x[:30])
            self.assertTrue(contains_credential({"a": [x]}), x[:30])

    def test_ordinary_words_that_merely_mention_secrets_are_not_blocked(self):
        for x in self.PLAIN:
            self.assertFalse(contains_credential(x), x)

    def test_the_chain_refuses_them_and_the_odd_field_names(self):
        t = pathlib.Path(tempfile.mkdtemp())
        d = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        for x in self.SHAPES:
            with self.assertRaises(RecordRefused, msg=x[:30]):
                d.record("X", {"note": x})
        for field in ("api_key", "apiKey", "API-KEY", "accessToken", "access_token", "Authorization", "client_secret", "privateKey", "password", "Seed", "credentials"):
            with self.assertRaises(RecordRefused, msg=field):
                d.record("X", {field: "v"})
        self.assertEqual(d.content.entries(), [])
        d.record("X", {"tokens_est": 12, "note": "the token budget is 500"})
        self.assertEqual(len(d.content.entries()), 1)


class C2_PlainNames(unittest.TestCase):
    """LOW. A name could be a Windows device (nul, aux, com1) or end in a dot or space, which Windows silently strips: two names for one folder."""

    def test_devices_trailing_dots_and_trailing_spaces_are_refused(self):
        for bad in ("nul", "NUL", "aux", "con", "com1", "LPT9", "nul.txt", "x.", "x ", "x..", "..", "a/b"):
            with self.assertRaises(sp.PathRefused, msg=repr(bad)):
                sp.safe_name(bad)
        for ok in ("graal-master", "llm.c", "Lib-master", "a b", "console", "auxiliary", "com10", "x.y"):
            self.assertEqual(sp.safe_name(ok), ok)


if __name__ == "__main__":
    unittest.main()
