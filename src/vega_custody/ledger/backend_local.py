"""backend_local.py - the always-on record: a hash-chained file on this machine."""
import pathlib


class BackendUnavailable(Exception):
    pass


class LocalBackend:
    name = "local"

    def __init__(self, path, required=True):
        self.path = pathlib.Path(path)
        self.required = required

    def check(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackendUnavailable(f"{self.name}: {exc}") from exc
