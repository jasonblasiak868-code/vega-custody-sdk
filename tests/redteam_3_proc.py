"""RED TEAM (custody, proc helper): a hostile child tries to flood, hang, ignore stdin, or outlive the kill."""
import os
import sys
import time
import unittest

from vega_custody import proc

PY = sys.executable


class T(unittest.TestCase):
    def test_a_well_behaved_child_returns_its_output_and_exit_code(self):
        r = proc.run_bounded([PY, "-I", "-c", "import sys; print('hi'); sys.stderr.write('e')"], timeout=20)
        self.assertEqual((r["status"], r["out"].strip(), r["err"], r["returncode"]), ("ok", b"hi", b"e", 0))

    def test_a_flood_is_cut_off_at_the_cap_and_the_child_killed(self):
        t0 = time.time()
        r = proc.run_bounded([PY, "-I", "-c", "import sys\nwhile True:\n    sys.stdout.write('x'*65536); sys.stdout.flush()"], timeout=30, cap=100_000)
        self.assertEqual(r["status"], "overflow")
        self.assertLessEqual(len(r["out"]), 100_001)
        self.assertTrue(r["kill_confirmed"])
        self.assertLess(time.time() - t0, 15)

    def test_a_hang_times_out_and_is_killed_and_confirmed(self):
        r = proc.run_bounded([PY, "-I", "-c", "import time; time.sleep(60)"], timeout=1)
        self.assertEqual(r["status"], "timeout")
        self.assertTrue(r["kill_confirmed"])

    def test_a_child_that_never_reads_a_huge_stdin_does_not_deadlock_the_caller(self):
        t0 = time.time()
        r = proc.run_bounded([PY, "-I", "-c", "import time; time.sleep(0.3); print('done')"], stdin_bytes=b"x" * 3_000_000, timeout=20)
        self.assertEqual((r["status"], r["out"].strip()), ("ok", b"done"))
        self.assertLess(time.time() - t0, 15)

    def test_a_grandchild_is_killed_with_the_tree(self):
        marker = os.path.join(os.environ.get("TEMP", "."), "vega_proc_grandchild_%d.txt" % os.getpid())
        if os.path.exists(marker):
            os.remove(marker)
        code = ("import subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-I','-c',\"import time;time.sleep(3);open(r'%s','w').write('alive')\"])\n"
                "time.sleep(60)" % marker.replace("\\", "/"))
        r = proc.run_bounded([PY, "-I", "-c", code], timeout=1)
        self.assertTrue(r["kill_confirmed"])
        time.sleep(4.5)
        self.assertFalse(os.path.exists(marker), "the grandchild survived the kill and wrote its marker")

    def test_a_process_that_cannot_be_confirmed_dead_is_reported_false(self):
        import subprocess

        class Stubborn:
            pid = 4194000

            def kill(self):
                pass

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("x", timeout)

            def poll(self):
                return None
        self.assertFalse(proc.kill_tree(Stubborn(), wait=0.05))


if __name__ == "__main__":
    unittest.main()
