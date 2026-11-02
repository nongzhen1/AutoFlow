"""One-time QR sign-in pairings for the Web console.

The signed-out device keeps a private poll token; the QR encodes a separate
scan code. An already signed-in device opens the scan code and approves it,
then the waiting device exchanges its poll token for a session exactly once.

The console runs as one uvicorn process (see ``login_guard``), so an in-memory
table is enough. Codes expire quickly and the table is bounded.
"""

from __future__ import annotations

import secrets
import threading
import time

PAIRING_TTL_SECONDS = 300
PAIRING_MAX_ENTRIES = 64

PENDING = "pending"
APPROVED = "approved"
USED = "used"
MISSING = "missing"


class PairingStore:
    def __init__(self, *, clock=time.monotonic, ttl=PAIRING_TTL_SECONDS, max_entries=PAIRING_MAX_ENTRIES):
        self._clock = clock
        self._ttl = max(30, int(ttl))
        self._max_entries = max(8, int(max_entries))
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}

    def _prune_locked(self, now):
        stale = [token for token, entry in self._entries.items() if entry["expires_at"] <= now]
        for token in stale:
            self._entries.pop(token, None)

    def create(self, *, requester_ip="", requester_agent="") -> dict:
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            if len(self._entries) >= self._max_entries:
                oldest = min(self._entries, key=lambda token: self._entries[token]["created_at"])
                self._entries.pop(oldest, None)
            poll_token = secrets.token_urlsafe(32)
            scan_code = secrets.token_urlsafe(16)
            self._entries[poll_token] = {
                "scan_code": scan_code,
                "created_at": now,
                "expires_at": now + self._ttl,
                "requester_ip": str(requester_ip or "")[:64],
                "requester_agent": str(requester_agent or "")[:180],
                "identity": None,
            }
            return {"poll_token": poll_token, "scan_code": scan_code, "expires_in": self._ttl}

    def scan_target(self, scan_code) -> dict | None:
        """Describe a scan code for the approval page, or return None."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            entry = self._find_locked(scan_code)
            if entry is None:
                return None
            return {
                "status": PENDING if entry["identity"] is None else APPROVED,
                "requester_ip": entry["requester_ip"],
                "expires_in": max(0, int(entry["expires_at"] - now)),
            }

    def approve(self, scan_code, identity) -> str:
        """Bind an identity to the scan code; returns APPROVED, USED or MISSING."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            entry = self._find_locked(scan_code)
            if entry is None:
                return MISSING
            if entry["identity"] is not None:
                return USED
            entry["identity"] = dict(identity)
            entry["approved_at"] = now
            return APPROVED

    def poll(self, poll_token) -> dict:
        """Return the pairing state; an approved pairing is consumed here."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            entry = self._entries.get(str(poll_token or ""))
            if entry is None:
                return {"status": USED, "expires_in": 0}
            if entry["identity"] is not None:
                identity = dict(entry["identity"])
                self._entries.pop(str(poll_token), None)
                return {"status": APPROVED, "identity": identity}
            return {"status": PENDING, "expires_in": max(0, int(entry["expires_at"] - now))}

    def _find_locked(self, scan_code):
        candidate = str(scan_code or "")
        if not candidate:
            return None
        try:
            encoded = candidate.encode("ascii")
        except UnicodeEncodeError:
            return None
        for entry in self._entries.values():
            if secrets.compare_digest(entry["scan_code"].encode("ascii"), encoded):
                return entry
        return None
