"""locations.py - the second chain: where each saved thing physically lives.

Every location entry points back at the content entry that created the thing and carries a digest READ BACK
from that location. A location that does not hold the exact bytes cannot be recorded."""
from vega_custody.dag.dag import Chain, RecordRefused

LOCATION_CLASSES = ("local", "external", "server")


class LocationChain(Chain):
    def __init__(self, paths, content: Chain):
        super().__init__(paths)
        self._content = content

    def record_location(self, content_entry_hash, location_class, uri, readback_sha256, **extra):
        if location_class not in LOCATION_CLASSES:
            raise RecordRefused(f"location class must be one of {LOCATION_CLASSES}")
        src = self._content.get(content_entry_hash)
        if src is None:
            raise RecordRefused("location points at a content entry that is not in the content DAG")
        want = src["payload"].get("data_sha256")
        if not want:
            raise RecordRefused("content entry carries no data_sha256 to check the location against")
        if readback_sha256 != want:
            raise RecordRefused("read-back digest at this location does not match the saved content")
        return self.record("LOCATION", {"content_entry": content_entry_hash, "location_class": location_class,
                                         "uri": uri, "readback_sha256": readback_sha256, **extra})

    def where(self, content_entry_hash):
        return [r for r in self.entries()
                if r["kind"] == "LOCATION" and r["payload"].get("content_entry") == content_entry_hash]
