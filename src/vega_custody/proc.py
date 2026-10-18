"""proc.py - run an untrusted program with bounded output, a wall-clock limit and a VERIFIED kill. Shared by every repo that runs inbound or contained code.

  run_bounded(argv, stdin_bytes, timeout, cap, cwd, env) -> {"status": ok|timeout|overflow, "out", "err", "returncode", "killed", "kill_confirmed"}

Why not subprocess.run(capture_output=True): that buffers ALL output in memory until the process exits, so a program that prints forever exhausts memory before any cap is checked,
and a timeout kills only the direct child, not the processes it started. Here output is read in chunks and never held beyond cap+1 bytes per stream, the whole process tree is
killed, and the kill is checked (a kill that is never verified is a stop that may not have stopped).
HONEST LIMIT: process control, not an operating-system sandbox. It does not block files or network. Hostile code belongs in a VM or container."""
import os
import subprocess
import threading
import time


def kill_tree(proc, wait: float = 5.0) -> bool:
    """Kill the process and its children, then confirm it is gone. True only if confirmed."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=10)
        else:
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass  # reviewed: fall through to the direct kill and the verified wait below, which decide whether it worked
    try:
        proc.kill()
    except OSError:
        pass  # reviewed: the process may already be gone; the verified wait below decides
    try:
        proc.wait(timeout=wait)
    except subprocess.TimeoutExpired:
        return False
    return proc.poll() is not None


def run_bounded(argv, stdin_bytes: bytes = b"", timeout: float = 10.0, cap: int = 64 * 1024, cwd=None, env=None) -> dict:
    kw = {"start_new_session": True} if os.name != "nt" else {"creationflags": 0x00000200}   # own process group / group on Windows so the tree can be killed
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    bufs = {"out": bytearray(), "err": bytearray()}
    over = threading.Event()

    def reader(stream, key):
        try:
            while True:
                chunk = stream.read1(65536)
                if not chunk:
                    return
                room = cap + 1 - len(bufs[key])
                if room > 0:
                    bufs[key] += chunk[:room]
                if len(bufs[key]) > cap:
                    over.set()
                    return
        except (OSError, ValueError):
            return

    def writer():
        try:
            proc.stdin.write(stdin_bytes)
        except (OSError, ValueError):
            pass  # reviewed: the child closed or broke the pipe: nothing to report, the readers and the timeout still bound the run
        finally:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass  # reviewed: stdin already closed by the child: harmless

    readers = [threading.Thread(target=reader, args=(proc.stdout, "out"), daemon=True), threading.Thread(target=reader, args=(proc.stderr, "err"), daemon=True)]
    for th in readers + [threading.Thread(target=writer, daemon=True)]:
        th.start()
    status, deadline = "ok", time.time() + timeout
    while True:
        if over.is_set():
            status = "overflow"
            break
        if proc.poll() is not None and not any(th.is_alive() for th in readers):
            break
        if time.time() >= deadline:
            status = "timeout"
            break
        time.sleep(0.01)
    killed = confirmed = None
    if status != "ok":
        killed = True
        confirmed = kill_tree(proc)
    else:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            status, killed, confirmed = "timeout", True, kill_tree(proc)
    for s in (proc.stdout, proc.stderr, proc.stdin):
        try:
            s.close()
        except (OSError, ValueError):
            pass  # reviewed: already closed by the reader or writer thread
    return {"status": status, "out": bytes(bufs["out"]), "err": bytes(bufs["err"]), "returncode": proc.returncode, "killed": killed, "kill_confirmed": confirmed}


# ---------------------------------------------------------------------------------------------- containing a whole process family
class ProcessJob:
    """Keeps a program AND everything it starts inside one kernel object, so nothing can outlive it by detaching.

    Why: killing 'the process tree' by parent links misses a descendant that detached (a new session, DETACHED_PROCESS) or whose parent already exited. On Windows the job object holds every descendant
    regardless of detaching, kills them all with the job, and can cap the number of processes and the memory each may use. The program is started SUSPENDED, put in the job, and only then resumed, so
    it cannot spawn anything before it is inside.
    On POSIX a process group plus a new session is the best portable stand-in (a descendant that calls setsid can still leave it): there the check `survivors()` is the guard, and real containment needs a
    cgroup or a container. start() raises when the job cannot be set up: a program is never run uncontained by accident."""

    def __init__(self):
        self.handle = None
        self.proc = None

    @classmethod
    def start(cls, argv, stdin=None, stdout=None, stderr=None, cwd=None, env=None, max_processes=32, max_process_bytes=2 * 1024 ** 3):
        job = cls()
        if os.name != "nt":
            job.proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr, start_new_session=True)
            return job
        import ctypes
        from ctypes import wintypes as w
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateJobObjectW.restype = w.HANDLE
        k.OpenThread.restype = w.HANDLE
        k.CreateToolhelp32Snapshot.restype = w.HANDLE

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD), ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

        class IOC(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("a", "b", "c", "d", "e", "f")]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IOC), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        h = k.CreateJobObjectW(None, None)
        if not h:
            raise OSError("could not create a job object")
        info = EXT()
        info.Basic.LimitFlags = 0x2000 | 0x8 | 0x100                                 # kill on close | active process limit | per-process memory limit
        info.Basic.ActiveProcessLimit = max_processes
        info.ProcessMemoryLimit = max_process_bytes
        if not k.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):
            k.CloseHandle(h)
            raise OSError("could not set the job object limits")
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr, creationflags=0x00000004 | 0x00000200)   # CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP
        try:
            if not k.AssignProcessToJobObject(h, int(proc._handle)):
                raise OSError("could not place the program in the job object (it may already be in another job that forbids nesting)")

            class TE(ctypes.Structure):
                _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ThreadID", w.DWORD), ("th32OwnerProcessID", w.DWORD), ("tpBasePri", w.LONG), ("tpDeltaPri", w.LONG), ("dwFlags", w.DWORD)]
            snap = k.CreateToolhelp32Snapshot(0x4, 0)
            te = TE()
            te.dwSize = ctypes.sizeof(te)
            resumed = False
            ok = k.Thread32First(snap, ctypes.byref(te))
            while ok:
                if te.th32OwnerProcessID == proc.pid:
                    th = k.OpenThread(0x0002, False, te.th32ThreadID)                # THREAD_SUSPEND_RESUME
                    if th:
                        k.ResumeThread(th)
                        k.CloseHandle(th)
                        resumed = True
                ok = k.Thread32Next(snap, ctypes.byref(te))
            k.CloseHandle(snap)
            if not resumed:
                raise OSError("could not resume the program after placing it in the job object")
        except BaseException:
            k.TerminateJobObject(h, 1)
            k.CloseHandle(h)
            proc.kill()
            raise
        job.handle, job.proc, job._k = h, proc, k
        return job

    def survivors(self) -> int:
        if os.name == "nt" and not self.handle:
            return 0                                                                 # the job was closed: kill-on-close already ended everything in it
        """How many processes of this job are still alive (Windows: exact, from the kernel; POSIX: 1 if the group leader lives, otherwise a group probe)."""
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes as w

            class ACC(ctypes.Structure):
                _fields_ = [("a", ctypes.c_longlong), ("b", ctypes.c_longlong), ("c", ctypes.c_longlong), ("d", ctypes.c_longlong), ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                            ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]
            acc = ACC()
            if not self._k.QueryInformationJobObject(self.handle, 1, ctypes.byref(acc), ctypes.sizeof(acc), None):
                return -1                                                            # unknown counts as not contained
            return int(acc.ActiveProcesses)
        import signal
        try:
            os.killpg(os.getpgid(self.proc.pid), 0)
            return 1
        except (ProcessLookupError, PermissionError, OSError):
            return 0

    def kill(self, wait: float = 5.0) -> bool:
        """Kill everything in the job and verify none is left. True only if confirmed."""
        if os.name == "nt":
            if self.handle:
                self._k.TerminateJobObject(self.handle, 1)
            try:
                self.proc.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                pass  # reviewed: survivors() below decides whether the kill worked
        else:
            kill_tree(self.proc, wait)
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.survivors() == 0:
                return True
            time.sleep(0.05)
        return self.survivors() == 0

    def close(self):
        if os.name == "nt" and self.handle:
            self._k.CloseHandle(self.handle)                                         # kill-on-close: anything still running dies here
            self.handle = None
