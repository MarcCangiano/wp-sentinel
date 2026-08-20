#!/usr/bin/env python3
"""
Reference webhook receiver for Sentinel.

The point of an off-box receiver is that it keeps working when the site does
not. Run it anywhere the sites can reach that they cannot modify.

    SENTINEL_SECRET=... python3 receiver.py

Verifies the HMAC before trusting anything in the payload, because the URL will
eventually leak and an unauthenticated alert endpoint is a way to be lied to
about which of your sites is on fire.
"""

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("SENTINEL_SECRET", "")
LOG = os.environ.get("SENTINEL_LOG", "sentinel.log")

# Anything in here is worth waking someone for. A heartbeat is not.
LOUD = {"admin_created", "admin_promoted", "core_modified", "files_appeared"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)

        if SECRET:
            sent = self.headers.get("X-Sentinel-Signature", "")
            want = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
            # compare_digest, not ==, so the comparison does not leak the
            # signature one byte at a time through timing.
            if not hmac.compare_digest(sent, want):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"bad signature")
                return

        try:
            payload = json.loads(body)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        received = datetime.now(timezone.utc).isoformat()
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"received": received, **payload}) + "\n")

        kind = payload.get("type", "?")
        site = payload.get("site", "?")
        if kind in LOUD:
            print(f"[ALERT] {site}: {payload.get('subject', kind)}", flush=True)
            # Wire your own paging in here — Telegram, SMS, PagerDuty.
        else:
            print(f"  ok    {site}: {kind}", flush=True)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # the handler above is the log


if __name__ == "__main__":
    if not SECRET:
        print("warning: SENTINEL_SECRET unset, accepting unsigned reports", file=sys.stderr)
    port = int(os.environ.get("PORT", 8099))
    print(f"listening on :{port}, writing {LOG}", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
