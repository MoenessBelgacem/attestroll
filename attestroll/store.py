# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Moeness Belgacem
"""SQLite persistence (stdlib only). Everything the hub must not lose on restart.
Writes are grouped in transactions via `with store.tx():` so a state change and its
audit entry are committed together or not at all."""
import contextlib, json, sqlite3, threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS releases    (product TEXT, version TEXT, manifest TEXT NOT NULL,
                                        signature TEXT NOT NULL, artifact BLOB NOT NULL,
                                        PRIMARY KEY (product, version));
CREATE TABLE IF NOT EXISTS rollouts    (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollments (device_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit       (seq INTEGER PRIMARY KEY, data TEXT NOT NULL);
"""


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self._depth = 0
        self._lock = threading.RLock()

    @contextlib.contextmanager
    def tx(self):
        with self._lock:
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if self._depth == 0:
                    self.db.rollback()
                raise
            else:
                self._depth -= 1
                if self._depth == 0:
                    self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()

    # -- writes
    def save_device(self, d):
        self.db.execute("INSERT OR REPLACE INTO devices VALUES (?,?)", (d["id"], json.dumps(d)))

    def save_release(self, product, version, manifest, signature, artifact):
        self.db.execute("INSERT INTO releases VALUES (?,?,?,?,?)",
                        (product, version, json.dumps(manifest), signature, artifact))

    def save_rollout(self, ro):
        self.db.execute("INSERT OR REPLACE INTO rollouts VALUES (?,?)", (ro["id"], json.dumps(ro)))

    def save_enrollment(self, device_id, token_hash):
        self.db.execute("INSERT OR REPLACE INTO enrollments VALUES (?,?)", (device_id, token_hash))

    def delete_enrollment(self, device_id):
        self.db.execute("DELETE FROM enrollments WHERE device_id=?", (device_id,))

    def append_audit(self, entry):
        self.db.execute("INSERT INTO audit VALUES (?,?)", (entry["seq"], json.dumps(entry)))

    # -- reads
    def load_devices(self):
        return {r[0]: json.loads(r[1]) for r in self.db.execute("SELECT id, data FROM devices")}

    def load_releases(self):
        out = {}
        for p, v, m, s, a in self.db.execute("SELECT product, version, manifest, signature, artifact FROM releases"):
            out[(p, v)] = dict(manifest=json.loads(m), signature=s, artifact=bytes(a))
        return out

    def load_rollouts(self):
        return {r[0]: json.loads(r[1]) for r in self.db.execute("SELECT id, data FROM rollouts")}

    def load_enrollments(self):
        return dict(self.db.execute("SELECT device_id, token_hash FROM enrollments"))

    def load_audit(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM audit ORDER BY seq")]
