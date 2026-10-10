"""Guard cases for the Temp drop burst summary (rule 100500, 2026-10-09).

Run inside the patched throwaway manager, next to replay.py. Every case
runs in its own logtest session (token), so the frequency state of one case
cannot leak into the next. Each event is sent with a one second gap because
analysisd keys the frequency window on whole seconds and treats the current
event's own second as the boundary, so events arriving within the same
second as the oldest counted one are not counted.
"""
import json
import socket
import struct
import sys
import time

SOCK = "/var/ossec/queue/sockets/logtest"


def ask(event, token=None, location="guard"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    params = {"event": json.dumps(event), "log_format": "syslog", "location": location}
    if token:
        params["token"] = token
    msg = json.dumps({"version": 1, "origin": {"name": "guard", "module": "guard"},
                      "command": "log_processing", "parameters": params}).encode()
    s.sendall(struct.pack("<I", len(msg)) + msg)
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    size, buf = struct.unpack("<I", hdr)[0], b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    data = json.loads(buf.decode(errors="replace").rstrip("\x00"))["data"]
    rule = data.get("output", {}).get("rule", {})
    return data.get("token"), rule.get("id", "none"), rule.get("level", 0), rule.get("description", "")


def p(path):
    # Field values carry doubled backslashes, as the agent sends them.
    return path.replace("\\", "\\\\")


def sysmon11(image, target, guid, user=r"Ben-Laptop\schug"):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "11",
                               "channel": "Microsoft-Windows-Sysmon/Operational", "severityValue": "INFORMATION"},
                    "eventdata": {"image": p(image), "targetFilename": p(target), "user": p(user),
                                  "processGuid": guid, "processId": "8068", "ruleName": "-",
                                  "utcTime": "2026-10-09 03:08:40.000"}}}


INSTALLER = r"C:\ProgramData\Intel\DSA\Downloads\gfx_win_101.7092.exe"
TEMP = r"C:\Users\schug\AppData\Local\Temp\RarSFX0\Graphics"
GUID_A = "{e76878a6-5a89-6ac8-843f-000000002600}"
GUID_B = "{e76878a6-5c74-6ac8-9b40-000000002600}"
CLAUDE = r"C:\Program Files\Git\usr\bin\bash.exe"
SCRATCH = r"C:\Users\schug\AppData\Local\Temp\claude\C--Users-schug-src\ca0943f2-7867-4a45-b615-2f078920b925\scratchpad"

failures = 0

# "--long N": send N files from one process and print the rule per event,
# to see how often the summary re-fires inside a long burst. No pass/fail.
if len(sys.argv) > 2 and sys.argv[1] == "--long":
    n, token, got = int(sys.argv[2]), None, []
    for i in range(n):
        token, rid, level, desc = ask(sysmon11(INSTALLER, TEMP + r"\lib%03d.dll" % i, GUID_A), token)
        got.append(rid)
        time.sleep(1.05)
    print("long burst x%d: %s" % (n, " ".join(got)))
    print("summaries: %d, dropped: %d" % (got.count("100500"), got.count("none")))
    raise SystemExit(0)


def run(name, events, expected):
    """events: list of dicts. expected: list of rule ids, one per event."""
    global failures
    token = None
    got = []
    summary = ""
    for ev in events:
        token, rid, level, desc = ask(ev, token)
        got.append(rid)
        if rid == "100500":
            summary = desc
        time.sleep(1.05)
    ok = got == expected
    failures += not ok
    print("%s %-40s %s" % ("PASS" if ok else "FAIL", name, " ".join(got)))
    if not ok:
        print("     expected: %s" % " ".join(expected))
    return summary


# 1. One installer process drops 14 executables: the first nine stay 92213,
#    the tenth becomes the 100500 summary, then 92213 again until the summary
#    drops out of the window.
evs = [sysmon11(INSTALLER, TEMP + r"\lib%02d.dll" % i, GUID_A) for i in range(14)]
desc = run("same guid x14", evs, ["92213"] * 9 + ["100500"] + ["92213"] * 4)
print("     summary description: %s" % desc)
if "$(" in desc or INSTALLER.split("\\")[-1] not in desc:
    failures += 1
    print("FAIL summary description did not expand the image field")

# 2. Two processes interleaved, seven files each: neither reaches ten.
evs = []
for i in range(7):
    evs.append(sysmon11(INSTALLER, TEMP + r"\a%02d.dll" % i, GUID_A))
    evs.append(sysmon11(INSTALLER, TEMP + r"\b%02d.dll" % i, GUID_B))
run("two guids x7 each, no summary", evs, ["92213"] * 14)

# 3. Events already demoted by 100243 (Claude scratchpad) never count.
#    (.ps1 is in 92213's extension list, .py is not and would only hit 61613.)
evs = [sysmon11(CLAUDE, SCRATCH + r"\s%02d.ps1" % i, GUID_A, user=r"Ben-PC\schug") for i in range(12)]
run("100243 drops do not count", evs, ["100243"] * 12)

# 4. Nine demoted events plus one real 92213 do not make a burst.
evs = [sysmon11(CLAUDE, SCRATCH + r"\s%02d.ps1" % i, GUID_A) for i in range(9)]
evs.append(sysmon11(INSTALLER, TEMP + r"\real.dll", GUID_A))
run("mixed: nine 100243 then one 92213", evs, ["100243"] * 9 + ["92213"])

# 5. uv launcher stubs are already handled by 100203 (level 0, 2026-10-06).
#    Twelve of them must stay there and must not build a 100500 burst; uv
#    writing any other executable into Temp still alerts at 15.
UV = r"C:\Users\schug\.local\bin\uv.exe"
UVTMP = r"C:\Users\schug\AppData\Local\Temp"
evs = [sysmon11(UV, UVTMP + r"\.tmp%06d\uv-trampoline-74140.exe" % i, GUID_B, user=r"Ben-PC\schug")
       for i in range(12)]
evs.append(sysmon11(UV, UVTMP + r"\.tmpabcdef\python.exe", GUID_B))
run("uv stubs x12 -> 100203, no burst", evs, ["100203"] * 12 + ["92213"])

# 6. 100203 is scoped to its writers (2026-10-09): the PowerShell engine and
#    uv. The same file names from cmd.exe stay at the stock level 15.
PS64 = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
PWSH = r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe"
POLICY = UVTMP + r"\__PSScriptPolicyTest_k2xq1abc.d3f.ps1"
evs = [sysmon11(PS64, POLICY, GUID_A, user=r"Ben-PC\schug"),
       sysmon11(PWSH, POLICY, GUID_A, user=r"Ben-PC\schug"),
       sysmon11(r"C:\Windows\System32\cmd.exe", POLICY, GUID_A),
       sysmon11(r"C:\Windows\System32\cmd.exe", UVTMP + r"\.tmpabcdef\uv-trampoline-1.exe", GUID_A),
       sysmon11(r"C:\Users\schug\Downloads\uv.exe", UVTMP + r"\.tmpabcdef\uv-trampoline-1.exe", GUID_A)]
run("100203 writer scope", evs, ["100203", "100203", "92213", "92213", "92213"])

print("\n%d failing case(s)" % failures)
raise SystemExit(1 if failures else 0)
