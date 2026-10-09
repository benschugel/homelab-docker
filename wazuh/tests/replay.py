"""Replay recorded Wazuh alerts through wazuh-logtest and report rule changes.

Runs inside a throwaway manager container whose stock rules 60000 and 19000
were patched to accept JSON, so Windows and SCA events can be re-evaluated.
Usage: replay.py <label> <alerts file> [<alerts file> ...]
"""
import collections
import gzip
import json
import socket
import struct
import sys

SOCK = "/var/ossec/queue/sockets/logtest"
label, files = sys.argv[1], sys.argv[2:]


def ask(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    msg = json.dumps(payload).encode()
    s.sendall(struct.pack("<I", len(msg)) + msg)
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    size, buf = struct.unpack("<I", hdr)[0], b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    return json.loads(buf.decode(errors="replace").rstrip("\x00"))


token = None
trans = collections.Counter()
before = collections.Counter()
after = collections.Counter()
paged_before = collections.Counter()
paged_after = collections.Counter()
warned = False
for f in files:
    day = f.split("/")[-1]
    op = gzip.open if f.endswith(".gz") else open
    with op(f, "rt", errors="replace") as fh:
        for line in fh:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            d = a.get("data", {})
            if "win" in d:
                ev = {"win": d["win"]}
            elif "sca" in d:
                ev = {"sca": d["sca"]}
            else:
                continue
            old = (a["rule"]["id"], a["rule"]["level"])
            p = {"event": json.dumps(ev), "log_format": "syslog", "location": "replay"}
            if token:
                p["token"] = token
            r = ask({"version": 1, "origin": {"name": "replay", "module": "replay"},
                     "command": "log_processing", "parameters": p})
            data = r.get("data", {})
            token = data.get("token", token)
            if not warned and data.get("messages"):
                bad = [m for m in data["messages"] if m.startswith(("WARNING", "ERROR"))]
                if bad:
                    print("LOGTEST MESSAGES:", bad[:5])
                    warned = True
            rule = data.get("output", {}).get("rule", {})
            new = (rule.get("id", "none"), rule.get("level", 0))
            trans[(old, new)] += 1
            before[day] += 1
            paged_before[day] += old[1] >= 10
            if new[1] > 0:
                after[day] += 1
                paged_after[day] += new[1] >= 10

print("=== %s ===" % label)
for day in before:
    print("%-28s alerts %5d -> %5d   level>=10 %4d -> %4d"
          % (day, before[day], after[day], paged_before[day], paged_after[day]))
print("--- changed outcomes (recorded -> replayed) ---")
for (old, new), n in sorted(trans.items(), key=lambda kv: -kv[1]):
    if old != new:
        print("%6d  %s L%s -> %s L%s" % (n, old[0], old[1], new[0], new[1]))
same = sum(n for (o, nw), n in trans.items() if o == nw)
print("unchanged: %d of %d" % (same, sum(trans.values())))
