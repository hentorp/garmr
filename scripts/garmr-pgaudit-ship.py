#!/usr/bin/env python3
"""Ship PostgreSQL pgAudit csvlog records to garmr's loki endpoint.

Follows the newest csvlog, reassembles multiline CSV records using CSV quote
state, ships only records containing
`AUDIT:` (the pgAudit rows) as a loki push with source=postgres-csvlog, so
garmr parses them through the pg adapter. --once = catch up existing records
and exit; default = follow.
"""
import glob, json, os, sys, time, urllib.request

GARMR = os.environ.get("GARMR_LOKI", "http://127.0.0.1:3105/loki/api/v1/push")
LOGDIR = os.environ.get("PG_LOGDIR", "/var/lib/postgresql/17/main/log")
HOST = os.environ.get("PG_HOST_LABEL", "pgdemo")

class CsvRecordBuffer:
    """Incrementally split CSV data only at newlines outside quoted fields."""

    def __init__(self):
        self.buf = []
        self.in_quotes = False

    def feed(self, data):
        records = []
        for char in data:
            self.buf.append(char)
            if char == '"':
                # A doubled quote toggles twice, leaving quote state unchanged.
                self.in_quotes = not self.in_quotes
            elif char == "\n" and not self.in_quotes:
                records.append("".join(self.buf).rstrip("\n"))
                self.buf = []
        return records

    def finish(self):
        if not self.buf:
            return []
        record = "".join(self.buf).rstrip("\n")
        self.buf = []
        return [record]

def newest():
    fs = sorted(glob.glob(os.path.join(LOGDIR, "*.csv")), key=os.path.getmtime)
    return fs[-1] if fs else None

def push(records):
    records = [r for r in records if "AUDIT:" in r]
    if not records:
        return 0
    now = time.time_ns()
    values = [[str(now + i), r] for i, r in enumerate(records)]
    body = json.dumps({"streams": [{"stream": {
        "source": "postgres-csvlog", "log_type": "audit",
        "host": HOST, "service": "postgres", "environment": "prod", "severity": "info",
    }, "values": values}]}).encode()
    req = urllib.request.Request(GARMR, data=body, headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status

def records_from(fh):
    """Yield CSV records, preserving newlines inside quoted fields."""
    parser = CsvRecordBuffer()
    for chunk in fh:
        yield from parser.feed(chunk)
    # In once mode, preserve the previous behavior for a final unterminated row.
    yield from parser.finish()

def main():
    once = "--once" in sys.argv
    path = newest()
    if not path:
        print("no csvlog", file=sys.stderr); return
    if once:
        with open(path) as fh:
            recs = list(records_from(fh))
        n = push(recs)
        print(f"shipped {sum('AUDIT:' in r for r in recs)} AUDIT records, http={n}")
        return
    # follow mode: start at EOF, ship new complete records
    pos = os.path.getsize(path)
    parser = CsvRecordBuffer()
    while True:
        cur = newest()
        if cur != path:  # rotated
            path, pos = cur, 0
            parser = CsvRecordBuffer()
        with open(path) as fh:
            fh.seek(pos)
            new = fh.read()
            pos = fh.tell()
        if new:
            for rec in parser.feed(new):
                if "AUDIT:" in rec:
                    try: push([rec])
                    except Exception as e: print(f"push err: {e}", file=sys.stderr)
        time.sleep(2)

if __name__ == "__main__":
    main()
