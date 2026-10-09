"""Guard cases: events that must KEEP alerting after tuning.

Run inside the patched throwaway manager, next to replay.py.
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
                                     "location": "guard"}}).encode()
    s.sendall(struct.pack("<I", len(msg)) + msg)
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    size, buf = struct.unpack("<I", hdr)[0], b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    rule = json.loads(buf.decode(errors="replace").rstrip("\x00"))["data"].get("output", {}).get("rule", {})
    return rule.get("id", "none"), rule.get("level", 0)


def sysmon(event_id, **eventdata):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": str(event_id),
                               "channel": "Microsoft-Windows-Sysmon/Operational",
                               "severityValue": "INFORMATION"},
                    "eventdata": eventdata}}


def sca(result, previous=None):
    check = {"id": "1", "title": "Example check", "result": result}
    if previous:
        check["previous_result"] = previous
    return {"sca": {"type": "check", "policy": "Example policy", "check": check}}


BS = "\\\\"  # the agent sends doubled backslashes


def p(path):
    return path.replace("\\", BS)


CASES = [
    ("SCA check regressed passed -> failed", sca("failed", "passed"), "19011", 9),
    ("SCA check newly failed from n/a", sca("failed", "not applicable"), "19014", 9),
    ("SCA plain failed result is silent", sca("failed"), "19007", 0),
    ("Exe dropped in Temp by unknown program",
     sysmon(11, image=p(r"C:\Users\schug\Downloads\setup.exe"),
            targetFilename=p(r"C:\Users\schug\AppData\Local\Temp\abc\payload.exe")), "92213", 15),
    ("Exe dropped in Temp by fake Steam path under user profile",
     sysmon(11, image=p(r"C:\Users\schug\Steam\bin\hardwareupdater\hardwareupdater.exe"),
            targetFilename=p(r"C:\Users\schug\AppData\Local\Temp\_MEI1234\evil.dll")), "92213", 15),
    ("Mullvad updater writing outside its NSIS temp folder",
     sysmon(11, image=p(r"C:\ProgramData\Mullvad VPN\cache\mullvad-update\mullvad-2026.5.exe"),
            targetFilename=p(r"C:\Users\schug\AppData\Local\Temp\evil.exe")), "92213", 15),
    ("svchost dropping DLL in System32",
     sysmon(11, image=p(r"C:\WINDOWS\system32\svchost.exe"),
            targetFilename=p(r"C:\Windows\System32\evil.dll")), "92219", 6),
    ("Netsh firewall rule added by something other than Tailscale",
     sysmon(1, image=p(r"C:\Windows\System32\netsh.exe"), originalFileName="netsh.exe",
            parentImage=p(r"C:\Users\schug\Downloads\tool.exe"),
            commandLine="netsh advfirewall firewall add rule name=Tailscale-In dir=in action=allow"), "92043", 10),
    ("Explorer started with an unusual command line",
     sysmon(1, image=p(r"C:\Windows\explorer.exe"), originalFileName="EXPLORER.EXE",
            parentImage=p(r"C:\Users\schug\Downloads\tool.exe"),
            commandLine=p(r"C:\Windows\explorer.exe C:\Users\Public")), "61640", 12),
    ("cmd started by an unknown program",
     sysmon(1, image=p(r"C:\Windows\System32\cmd.exe"), originalFileName="Cmd.Exe",
            parentImage=p(r"C:\Users\schug\Downloads\tool.exe"),
            commandLine=p(r"C:\WINDOWS\system32\cmd.exe /c whoami")), "92052", 4),
    ("Chrome launching an unknown native host",
     sysmon(1, image=p(r"C:\Windows\System32\cmd.exe"), originalFileName="Cmd.Exe",
            parentImage=p(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            commandLine=p(r'C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\Users\schug\AppData\Roaming\x\host.exe" '
                          r'chrome-extension://abcdefghijklmnopabcdefghijklmnop/ --parent-window=0"')), "92052", 4),
    ("New non per-user service registered",
     sysmon(13, image=p(r"C:\WINDOWS\system32\services.exe"),
            targetObject=p(r"HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath"),
            details=p(r"C:\Users\Public\evil.exe")), "92307", 3),
    ("PowerShell writing a real script into Windows Temp",
     sysmon(11, image=p(r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"),
            targetFilename=p(r"C:\Windows\Temp\stage2.ps1")), "92201", 9),
]

failed = 0
for name, event, want_id, want_level in CASES:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed += not ok
    print("%-4s %-58s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("guard cases failed: %d of %d" % (failed, len(CASES)))
