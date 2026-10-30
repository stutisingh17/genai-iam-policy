"""Stage 11: append-only, hash-chained audit log (JSON Lines). Tampering breaks the chain."""
import hashlib
import json
import os
import time


class AuditLog:
    def __init__(self, path):
        self.path = path
        self.prev = "0" * 64
        self.seq = 0
        if os.path.exists(path):
            ok, n, last = self.verify(path)
            if not ok:
                raise RuntimeError("audit log failed integrity check; refusing to append")
            self.seq, self.prev = n, last

    def log(self, stage, data):
        entry = {"seq": self.seq + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "stage": stage,
                 "data": data, "prev": self.prev}
        entry["hash"] = hashlib.sha256((self.prev + json.dumps({k: entry[k] for k in ("seq", "ts", "stage", "data")},
                                                               sort_keys=True)).encode()).hexdigest()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self.seq, self.prev = entry["seq"], entry["hash"]

    @staticmethod
    def verify(path):
        prev, n = "0" * 64, 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                h = hashlib.sha256((prev + json.dumps({k: e[k] for k in ("seq", "ts", "stage", "data")},
                                                      sort_keys=True)).encode()).hexdigest()
                if e["prev"] != prev or e["hash"] != h or e["seq"] != n + 1:
                    return False, n, prev
                prev, n = h, n + 1
        return True, n, prev
