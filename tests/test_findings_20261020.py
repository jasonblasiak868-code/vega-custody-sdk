"""Regression tests (2026-10-20): (1) minting the same commitment from two threads recorded it twice, so 'a commitment is single use' did not hold at the ledger;
(2) on POSIX the process-group lookups used os.getpgid(pid), which fails once the leader has been reaped, so a descendant that outlived the job went undetected
(and was not killed) exactly when that check matters. The POSIX logic is exercised here with a stand-in for the OS calls."""
import os
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from vega_custody import proc
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger, LedgerRefused


class MintRace(unittest.TestCase):
    def test_two_threads_minting_one_commitment_record_it_once(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger([LocalBackend(os.path.join(d, "led.jsonl"))])
            for n in range(25):
                c = {"kind": "OTHER", "action": "a", "action_hash": "%064x" % n, "expiry": 9999999999, "nonce_sha256": "%064x" % (n + 1000)}
                gate, results, lock = threading.Barrier(2), [], threading.Lock()

                def go():
                    gate.wait()
                    try:
                        led.mint(c)
                        r = "minted"
                    except LedgerRefused:
                        r = "refused"
                    with lock:
                        results.append(r)
                ts = [threading.Thread(target=go) for _ in range(2)]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join(30)
                self.assertEqual(sorted(results), ["minted", "refused"], "attempt %d: %s" % (n, results))
            mints = [e for e in led.chain.entries() if e["kind"] == "MINT"]
            self.assertEqual(len(mints), 25)
            self.assertEqual(len({e["payload"]["leaf"] for e in mints}), 25)


class FakePosix:
    """Stands in for the OS: one process group (id 4242) whose leader (pid 4242) has been reaped but which still holds a live descendant."""

    def __init__(self, group=4242):
        self.group = group
        self.group_alive = True
        self.killed = []

    def getpgid(self, pid):
        raise ProcessLookupError(pid)                  # the leader is gone: asking for ITS group fails

    def killpg(self, pgid, sig):
        if pgid != self.group or not self.group_alive:
            raise ProcessLookupError(pgid)
        if sig == 0:
            return
        self.killed.append((pgid, sig))
        self.group_alive = False


class PosixGroupLookups(unittest.TestCase):
    def setUp(self):
        self.os = FakePosix()
        self.p = mock.patch.multiple(os, name="posix", create=True, getpgid=self.os.getpgid, killpg=self.os.killpg)
        self.p.start()
        self.addCleanup(self.p.stop)
        self.sig = mock.patch.object(signal, "SIGKILL", 9, create=True)       # Windows has no SIGKILL; the POSIX branch is exercised with stand-ins
        self.sig.start()
        self.addCleanup(self.sig.stop)
        self.job = proc.ProcessJob()
        self.job.proc = mock.Mock(pid=4242)
        self.job.pgid = 4242                           # start() records the group id: it is the leader's pid because the child is started in its own session

    def test_a_descendant_that_outlives_a_reaped_leader_is_counted(self):
        self.assertEqual(self.job.survivors(), 1)

    def test_no_survivors_once_the_group_is_empty(self):
        self.os.group_alive = False
        self.assertEqual(self.job.survivors(), 0)

    def test_kill_tree_kills_the_group_even_when_the_leader_was_reaped(self):
        p = mock.Mock(pid=4242)
        p.poll.return_value = 0
        p.wait.return_value = 0
        proc.kill_tree(p, wait=0.1, pgid=4242)
        self.assertEqual(self.os.killed, [(4242, 9)])

    def test_kill_tree_falls_back_to_the_process_id_when_the_group_cannot_be_looked_up(self):
        p = mock.Mock(pid=4242)
        p.poll.return_value = 0
        p.wait.return_value = 0
        proc.kill_tree(p, wait=0.1)                    # no pgid given, and getpgid fails because the leader is gone
        self.assertEqual(self.os.killed, [(4242, 9)])

    def test_the_job_kill_uses_the_group_id_it_recorded_and_confirms_the_group_is_empty(self):
        self.os.group = 7001                           # deliberately not the leader's pid: the job must use what it recorded at start, not guess from the pid
        self.job.pgid = 7001
        self.job.proc.poll.return_value = 0
        self.job.proc.wait.return_value = 0
        self.assertTrue(self.job.kill(wait=0.2))
        self.assertEqual(self.os.killed, [(7001, 9)])


if __name__ == "__main__":
    unittest.main()
