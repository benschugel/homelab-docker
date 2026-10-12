"""Guard cases for the 2026-10-11 Edge component unpack (rule 100222 extended
to msedge.exe).

Run inside the patched throwaway manager, next to replay.py.
"""
import json
import socket
import struct

SOCK = "/var/ossec/queue/sockets/logtest"


def ask(event, location="guard"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    msg = json.dumps({"version": 1, "origin": {"name": "guard", "module": "guard"},
                      "command": "log_processing",
                      "parameters": {"event": event if isinstance(event, str) else json.dumps(event),
                                     "log_format": "syslog", "location": location}}).encode()
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


def p(path):
    # Field values carry doubled backslashes, as the agent sends them.
    return path.replace("\\", "\\\\")


def sysmon11(image, target, user=r"hx-102\user"):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "11",
                               "channel": "Microsoft-Windows-Sysmon/Operational", "severityValue": "INFORMATION"},
                    "eventdata": {"image": p(image), "targetFilename": p(target), "user": p(user),
                                  "processId": "1424", "ruleName": "DLL"}}}


EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
WEBVIEW = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.3537.71\msedgewebview2.exe"
UNPACK = r"C:\Users\user\AppData\Local\Temp\msedge_chrome_Unpacker_BeginUnzipping1424_132176433\well_known_domains.dll"

CASES = [
    ("Edge component unpack (alert of 2026-10-12 03:35 UTC)", sysmon11(EDGE, UNPACK), "100222", 3),
    ("Edge unpack, nested exe", sysmon11(EDGE, UNPACK.replace("well_known_domains.dll", r"x\setup.exe")), "100222", 3),
    ("WebView2 unpack still lowered", sysmon11(WEBVIEW, UNPACK), "100222", 3),
    ("Edge dropping a plain DLL in Temp is NOT lowered",
     sysmon11(EDGE, r"C:\Users\user\AppData\Local\Temp\payload.dll"), "92213", 15),
    ("Edge dropping into a look-alike Unpacker name is NOT lowered",
     sysmon11(EDGE, r"C:\Users\user\AppData\Local\Temp\msedge_chrome_Unpacker_BeginUnzippingX_1\a.dll"), "92213", 15),
    ("msedge.exe outside Program Files is NOT lowered",
     sysmon11(r"C:\Users\user\AppData\Local\Temp\Microsoft\Edge\Application\msedge.exe", UNPACK), "92213", 15),
    ("msedge.exe under Program Files\\Evil prefix is NOT lowered",
     sysmon11(r"C:\Program Files (x86)\Evil\Microsoft\Edge\Application\msedge.exe", UNPACK), "92213", 15),
    ("Other Edge binary (msedge_proxy) is NOT lowered",
     sysmon11(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe", UNPACK), "92213", 15),
]

failed = 0
for name, event, want_id, want_level in CASES:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed += not ok
    print("%-4s %-60s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("edge cases failed: %d of %d" % (failed, len(CASES)))
