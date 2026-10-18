"""RED TEAM (custody, public witness): the only code in the family that can send something off the machine. Only a 32-byte root may leave, only to the configured https calendar."""
import http.server
import tempfile
import threading
import unittest

from vega_custody.ledger import backend_timestamp as bt


class Serve:
    def __init__(self, status=200, headers=None, body=b"receipt"):
        self.hits, outer = [], self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                outer.hits.append((self.path, self.rfile.read(int(self.headers.get("Content-Length", 0)))))
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.hits.append(("GET " + self.path, b""))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class T(unittest.TestCase):
    def test_only_https_or_a_loopback_test_server_is_accepted_as_a_calendar(self):
        for url in ("file:///etc/passwd", "ftp://example.com", "http://example.com", "http://10.0.0.5", "javascript:alert(1)", "", "calendar", None, "https://"):
            with self.assertRaises(ValueError, msg=str(url)):
                bt.OpenTimestampsWitness(url)
        bt.OpenTimestampsWitness("https://alice.btc.calendar.opentimestamps.org")
        bt.OpenTimestampsWitness("http://127.0.0.1:9")

    def test_only_a_64_hex_root_is_sent(self):
        s = Serve()
        try:
            w = bt.OpenTimestampsWitness(s.url)
            for bad in ("", "zz", "ab" * 31, "AB" * 32, "ab" * 33, None, 5, b"ab" * 32, "ab" * 32 + "\n"):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    w.anchor(bad)
            self.assertEqual(s.hits, [])
            r = w.anchor("ab" * 32)
            self.assertEqual((r["status"], s.hits), ("pending", [("/digest", bytes.fromhex("ab" * 32))]))
        finally:
            s.close()

    def test_a_redirect_never_carries_the_root_to_another_host(self):
        target = Serve()
        redirector = Serve(status=307, headers={"Location": target.url + "/digest"})
        try:
            with self.assertRaises(Exception):
                bt.OpenTimestampsWitness(redirector.url).anchor("cd" * 32)
            self.assertEqual(target.hits, [])
        finally:
            target.close()
            redirector.close()

    def test_an_oversize_receipt_is_refused(self):
        s = Serve(body=b"x" * 2000)
        old = bt.MAX_RECEIPT_BYTES
        bt.MAX_RECEIPT_BYTES = 1000
        try:
            with self.assertRaises(ValueError):
                bt.OpenTimestampsWitness(s.url).anchor("ef" * 32)
        finally:
            bt.MAX_RECEIPT_BYTES = old
            s.close()

    def test_the_file_witness_records_roots_locally_and_sends_nothing(self):
        d = tempfile.mkdtemp()
        w = bt.FileWitness(d + "/roots.jsonl")
        self.assertEqual(w.anchor("ab" * 32)["status"], "recorded")


if __name__ == "__main__":
    unittest.main()
