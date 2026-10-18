"""backend_drive.py - the same record on a USB stick or external drive: free, offline, yours.
Unlike the local backend it never creates the drive's root: if the drive is not mounted the check fails, so a
mint is refused (or marked degraded when the backend is optional) instead of silently writing to the wrong disk."""
import os
import pathlib

from vega_custody.ledger.backend_local import BackendUnavailable


class DriveBackend:
    name = "drive"

    def __init__(self, path, mount_point=None, required=True, verify_mount=True):
        self.path = pathlib.Path(path)
        if mount_point is None and self.path.anchor in ("/", ""):
            raise BackendUnavailable("a mount_point is required on this OS: '/' is always a directory, so an unplugged drive would silently write to the system disk")
        self.mount_point = pathlib.Path(mount_point) if mount_point else pathlib.Path(self.path.anchor)
        self.required = required
        self.verify_mount = verify_mount     # True: the mount point must be a real mount (a drive root or mounted volume), not just an existing folder; False only for tests

    def check(self):
        if not self.mount_point.is_dir() or (self.verify_mount and not os.path.ismount(self.mount_point)):
            raise BackendUnavailable(f"drive not mounted: {self.mount_point}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackendUnavailable(f"drive not writable: {exc}") from exc
