"""backend_timestamp.py - public witnesses: someone outside your machine can later prove the record existed by
a given time. Only a Merkle ROOT (32 bytes of hash) ever leaves; no commitment content, no metadata.

A witness is optional and OFF by default. Using a network witness sends the root to a third party, so it is only
constructed when the owner configures it.

  FileWitness            writes roots to a local file (feed it to `ots stamp` or any notary by hand). Tested.
  OpenTimestampsWitness  posts the root to a public OpenTimestamps calendar (Bitcoin-anchored, free).
                         The request shape follows the OpenTimestamps calendar protocol but has NOT been run
                         live from this SDK; treat it as unverified until you have a stored receipt and have
                         upgraded/verified it with the reference `ots` client.
"""
import base64
import datetime
import json
import pathlib
import re
import urllib.parse
import urllib.request

DEFAULT_CALENDAR = "https://alice.btc.calendar.opentimestamps.org"


class Witness:
    def anchor(self, root_hex: str) -> dict:
        raise NotImplementedError


class FileWitness(Witness):
    def __init__(self, path):
        self.path = pathlib.Path(path)

    def anchor(self, root_hex: str) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"root": root_hex, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return {"witness": "file", "path": str(self.path), "status": "recorded"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


MAX_RECEIPT_BYTES = 1024 * 1024


class OpenTimestampsWitness(Witness):
    """Posts a 32-byte root to a calendar. The URL must be https (http only for a loopback test server), redirects are not followed (a calendar must not hand the root to another
    host), the root must be exactly 64 hex characters, and the receipt is size-capped."""

    def __init__(self, calendar_url=DEFAULT_CALENDAR, timeout=20):
        u = urllib.parse.urlparse(str(calendar_url))
        loopback = u.hostname in ("127.0.0.1", "localhost", "::1")
        if not u.hostname or u.scheme not in ("https", "http") or (u.scheme == "http" and not loopback):
            raise ValueError("a calendar URL must be https (http only for a loopback test server): the root would otherwise travel in the clear or be read from a file")
        self.calendar_url, self.timeout = str(calendar_url).rstrip("/"), timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def anchor(self, root_hex: str) -> dict:
        if not isinstance(root_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", root_hex):
            raise ValueError("a root is 64 lowercase hex characters")
        req = urllib.request.Request(
            self.calendar_url + "/digest", data=bytes.fromhex(root_hex), method="POST",
            headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "vega-sdk",
                     "Content-Type": "application/x-www-form-urlencoded"})
        with self._opener.open(req, timeout=self.timeout) as resp:
            body = resp.read(MAX_RECEIPT_BYTES + 1)
        if len(body) > MAX_RECEIPT_BYTES:
            raise ValueError("calendar receipt is larger than the limit")
        return {"witness": "opentimestamps", "calendar": self.calendar_url, "status": "pending",
                "receipt_b64": base64.b64encode(body).decode("ascii")}
