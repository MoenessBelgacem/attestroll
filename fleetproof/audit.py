"""Append-only audit log. Each entry includes the hash of the previous one, so any
later modification of history is detectable (tamper-evident)."""
import datetime, json
from .crypto import sha256_hex, canonical

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, entries=None, sink=None):
        self.entries = list(entries or [])
        self.sink = sink            # called with every new entry (e.g. to persist it)

    def append(self, actor: str, action: str, detail: dict):
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {
            "seq": len(self.entries),
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "actor": actor, "action": action, "detail": detail, "prev": prev,
        }
        entry = dict(body, hash=sha256_hex(canonical(body)))
        self.entries.append(entry)
        if self.sink:
            self.sink(entry)
        return entry

    def verify(self):
        """Returns (ok, index_of_first_bad_entry_or_None)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: e[k] for k in ("seq", "ts", "actor", "action", "detail", "prev")}
            if e["prev"] != prev or e["hash"] != sha256_hex(canonical(body)):
                return False, i
            prev = e["hash"]
        return True, None
