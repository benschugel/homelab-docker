"""Guard cases for the 2026-10-08 evening level-10 triage (rules 100244, 100245).

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


def p(s):
    # Field values carry doubled backslashes and escaped quotes, as the agent sends them.
    return s.replace("\\", "\\\\").replace('"', '\\"')


def sysmon1(image, original, cmdline, parent, user=r"NT AUTHORITY\SYSTEM"):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1",
                               "channel": "Microsoft-Windows-Sysmon/Operational", "severityValue": "INFORMATION"},
                    "eventdata": {"image": p(image), "originalFileName": original, "commandLine": p(cmdline),
                                  "parentImage": p(parent), "user": p(user), "integrityLevel": "System",
                                  "processId": "1234"}}}


REG = r"C:\Windows\System32\reg.exe"
NETSH = r"C:\Windows\System32\netsh.exe"
CMD = r"C:\Windows\System32\cmd.exe"
DISCORD = r"C:\Users\schug\AppData\Local\Discord\app-1.0.9260\Discord.exe"
DBX_INSTALLER = r"C:\Windows\SystemTemp\dropbox_Unpacker_BeginUnzipping9948_1127445525\app\Dropbox.exe"
DBX_RULE = r'add rule name=Dropbox dir=in action=allow "program=C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
UNINST_HKLM = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall"
UNINST_HKCU = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"

CASES = [
    # 100244: installer uninstall-key writes, level 3
    ("RustDesk installer EstimatedSize (SYSTEM via cmd)",
     sysmon1(REG, "reg.exe", r"reg  add %s\RustDesk /f /v EstimatedSize /t REG_DWORD /d 76196" % UNINST_HKLM, CMD),
     "100244", 3),
    ("RustDesk installer DisplayIcon path",
     sysmon1(REG, "reg.exe", r'reg  add %s\RustDesk /f /v DisplayIcon /t REG_SZ /d "C:\Program Files\RustDesk\RustDesk.exe"' % UNINST_HKLM, CMD),
     "100244", 3),
    ("RustDesk installer BuildDate",
     sysmon1(REG, "reg.exe", r'reg  add %s\RustDesk /f /v BuildDate /t REG_SZ /d "2026-09-30 17:00"' % UNINST_HKLM, CMD),
     "100244", 3),
    ("Discord updater DisplayVersion (user, HKCU)",
     sysmon1(r"C:\Windows\System32\reg.exe", "reg.exe",
             r"C:\WINDOWS\System32\reg.exe add %s\Discord /v DisplayVersion /d 1.0.9261 /f" % UNINST_HKCU,
             DISCORD, r"Ben-PC\schug"), "100244", 3),
    ("Uninstall key write with a non-standard value name is NOT lowered",
     sysmon1(REG, "reg.exe", r"reg add %s\Foo /v Payload /d aGVsbG8gd29ybGQ= /f" % UNINST_HKLM, CMD),
     "92041", 10),
    ("Run key write from cmd.exe is NOT lowered",
     sysmon1(REG, "reg.exe", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d aGVsbG8gd29ybGQ= /f", CMD),
     "92041", 10),
    ("Uninstall key write from an unknown parent is NOT lowered",
     sysmon1(REG, "reg.exe", r"reg add %s\Foo /v DisplayVersion /d 1.0.9261 /f" % UNINST_HKLM,
             r"C:\Users\schug\Downloads\setup.exe", r"Ben-PC\schug"), "92041", 10),
    ("Discord look-alike outside AppData is NOT lowered",
     sysmon1(REG, "reg.exe", r"reg add %s\Discord /v DisplayVersion /d 1.0.9261 /f" % UNINST_HKCU,
             r"C:\Users\Public\Discord\app-1.0.9260\Discord.exe", r"Ben-PC\schug"), "92041", 10),
    # 100245: Dropbox installer firewall rules, level 3
    ("Dropbox installer UDP 17500 rule",
     sysmon1(NETSH, "netsh.exe", r"C:\WINDOWS\system32\netsh.exe advfirewall firewall %s protocol=udp localport=17500" % DBX_RULE, DBX_INSTALLER),
     "100245", 3),
    ("Dropbox installer TCP 17500-17510 rule",
     sysmon1(NETSH, "netsh.exe", r"C:\WINDOWS\system32\netsh.exe advfirewall firewall %s protocol=tcp localport=17500-17510" % DBX_RULE, DBX_INSTALLER),
     "100245", 3),
    ("Dropbox installer opening a different port is NOT lowered",
     sysmon1(NETSH, "netsh.exe", r"C:\WINDOWS\system32\netsh.exe advfirewall firewall %s protocol=tcp localport=4444" % DBX_RULE, DBX_INSTALLER),
     "92043", 10),
    ("Dropbox-named rule for another program is NOT lowered",
     sysmon1(NETSH, "netsh.exe", r'C:\WINDOWS\system32\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow "program=C:\Users\schug\AppData\Local\Temp\x.exe" enable=yes profile=Any protocol=tcp localport=17500', DBX_INSTALLER),
     "92043", 10),
    ("Dropbox rule from a non-installer parent is NOT lowered",
     sysmon1(NETSH, "netsh.exe", r"C:\WINDOWS\system32\netsh.exe advfirewall firewall %s protocol=udp localport=17500" % DBX_RULE,
             r"C:\Users\schug\AppData\Local\Temp\Dropbox.exe", r"Ben-PC\schug"), "92043", 10),
    ("Tailscale rule still handled by 100229",
     sysmon1(NETSH, "netsh.exe", r"C:\WINDOWS\system32\netsh.exe advfirewall firewall add rule name=Tailscale-In dir=in action=allow localip=100.72.56.17/32 profile=private,domain enable=yes",
             r"C:\Program Files\Tailscale\tailscaled.exe"), "100229", 3),
]

failed = 0
for name, event, want_id, want_level in CASES:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed += not ok
    print("%-4s %-62s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("cases failed: %d of %d" % (failed, len(CASES)))
