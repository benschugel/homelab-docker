"""Guard cases for the medium-band tuning (rules 100230-100234).

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


def win(channel, provider, event_id, message, **eventdata):
    return {"win": {"system": {"providerName": provider, "eventID": str(event_id), "channel": channel,
                               "severityValue": "ERROR" if channel == "Application" else "AUDIT_SUCCESS",
                               "message": message},
                    "eventdata": eventdata}}


ATTRS = ["SAM Account Name", "Display Name", "User Principal Name", "Home Directory", "Home Drive",
         "Script Path", "Profile Path", "User Workstations", "Password Last Set", "Account Expires",
         "Primary Group ID", "AllowedToDelegateTo", "Old UAC Value", "New UAC Value",
         "User Account Control", "User Parameters", "SID History", "Logon Hours"]


def acct(subject_sid="S-1-5-18", subject_name="BEN-PC$", **changed):
    """Build a 4738 event. `changed` maps attribute display names to values; the rest read '-'."""
    changed.setdefault("Display Name", "Ben Schugel")
    lines = "".join("\r\n\t%s:\t%s" % (k, changed.get(k, "-")) for k in ATTRS)
    message = ("A user account was changed.\r\n\r\nSubject:\r\n\tSecurity ID:\t\t%s\r\n\tAccount Name:\t\t%s\r\n"
               "\r\nTarget Account:\r\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1001\r\n\tAccount Name:\t\tschug\r\n"
               "\r\nChanged Attributes:%s\r\n\r\nAdditional Information:\r\n\tPrivileges:\t\t-" % (subject_sid, subject_name, lines))
    eventdata = dict(targetUserName="schug", targetDomainName="Ben-PC", targetSid="S-1-5-21-1-2-3-1001",
                     subjectUserSid=subject_sid, subjectUserName=subject_name, subjectDomainName="WORKGROUP",
                     subjectLogonId="0x3e7", displayName=changed["Display Name"])
    return win("Security", "Microsoft-Windows-Security-Auditing", 4738, message, **eventdata)


CASES = [
    ("Account refresh by SYSTEM, display name only", acct(), "100233", 3),
    ("Account change by SYSTEM with password set", acct(**{"Password Last Set": "10/7/2026 1:00:00 AM"}), "60110", 8),
    ("Account change by SYSTEM with UAC change", acct(**{"Old UAC Value": "0x210", "New UAC Value": "0x211", "User Account Control": "%%2080"}), "60110", 8),
    ("Account change by SYSTEM with SID history", acct(**{"SID History": "S-1-5-21-9-9-9-500"}), "60110", 8),
    ("Account change by SYSTEM with group change", acct(**{"Primary Group ID": "544"}), "60110", 8),
    ("Account change by an interactive user", acct(subject_sid="S-1-5-21-1-2-3-1001", subject_name="schug"), "60110", 8),
    ("Restart Manager could not restart app",
     win("Application", "Microsoft-Windows-RestartManager", 10010,
         "Application or service 'Intel(R) Driver & Support Assistant' could not be restarted."), "100231", 3),
    ("Intel DSA .NET launch failure",
     win("Application", ".NET Runtime", 1023,
         "Description: A .NET application failed. Application: DSAServiceHelper.exe Path: C:\\Program Files (x86)\\Intel"), "100232", 5),
    ("Phone Link crash",
     win("Application", "Application Error", 1000,
         "Faulting application name: PhoneExperienceHost.exe, version: 1.2.3, time stamp: 0x1"), "100232", 5),
    ("Unknown app crash stays level 9",
     win("Application", "Application Error", 1000,
         "Faulting application name: chrome.exe, version: 1.2.3, time stamp: 0x1"), "60602", 9),
    ("Unknown .NET unhandled exception stays level 9",
     win("Application", ".NET Runtime", 1026,
         "Application: SomethingElse.exe CoreCLR Version: 10.0 Description: The process was terminated"), "61017", 9),
]

failed = 0
for name, event, want_id, want_level in CASES:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed += not ok
    print("%-4s %-50s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))

# Rootcheck and syscheck events are not re-decodable through logtest; try anyway and report.
for name, event, loc in [
    ("rootcheck TLS file (informational, may be untestable)",
     "File '/etc/ssl/filebeat.pem' is owned by root and has written permissions to anyone.", "rootcheck"),
]:
    print("info %-50s got %s L%s" % (name, *ask(event, loc)))
print("guard cases failed: %d of %d" % (failed, len(CASES)))


# SteelSeries poll (rules 100236/100237): same name on both sides, SteelSeries vocabulary only.
def p(path):
    return path.replace("\\", "\\\\")


def sysmon1(**eventdata):
    # Field values carry doubled backslashes, as the agent sends them.
    base = dict(user=p(r"NT AUTHORITY\SYSTEM"), originalFileName="Cmd.Exe", image=p(r"C:\Windows\System32\cmd.exe"),
                parentImage=p(r"C:\ProgramData\SteelSeries\GG\updates\Setup.exe"))
    base.update(eventdata)
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1",
                               "channel": "Microsoft-Windows-Sysmon/Operational", "severityValue": "INFORMATION"},
                    "eventdata": base}}


poll = 'cmd /c tasklist /nh /fi \\"imagename eq %s.exe\\" | find /i \\"%s.exe\\"'
MORE = [
    ("SteelSeries poll for SteelSeriesGGEZ", sysmon1(commandLine=poll % ("SteelSeriesGGEZ", "SteelSeriesGGEZ")), "100236", 0),
    ("SteelSeries poll for 3dat", sysmon1(commandLine=poll % ("3dat", "3dat")), "100236", 0),
    ("Poll for Defender process is NOT ignored", sysmon1(commandLine=poll % ("MsMpEng", "MsMpEng")), "92052", 4),
    ("Mismatched names are NOT ignored", sysmon1(commandLine=poll % ("SteelSeriesGG", "MsMpEng")), "92052", 4),
    ("Same poll by a normal user is NOT ignored", sysmon1(user=p(r"Ben-PC\schug"), commandLine=poll % ("SteelSeriesGG", "SteelSeriesGG")), "92052", 4),
]
failed2 = 0
for name, event, want_id, want_level in MORE:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed2 += not ok
    print("%-4s %-50s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("steelseries cases failed: %d of %d" % (failed2, len(MORE)))
