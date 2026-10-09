"""Guard cases for the 2026-10-08 triage (rules 100240-100243).

Run inside the patched throwaway manager, next to replay.py. The UniFi cases
need unifi_decoder.xml in /var/ossec/etc/decoders and unifi_rules.xml in
/var/ossec/etc/rules of that manager.
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


def sysmon11(image, target, user=r"NT AUTHORITY\SYSTEM"):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "11",
                               "channel": "Microsoft-Windows-Sysmon/Operational", "severityValue": "INFORMATION"},
                    "eventdata": {"image": p(image), "targetFilename": p(target), "user": p(user),
                                  "processId": "1234", "ruleName": "-"}}}


def svc7045(name, path, kind, start="demand start"):
    return {"win": {"system": {"providerName": "Service Control Manager", "eventID": "7045", "channel": "System",
                               "severityValue": "INFORMATION",
                               "message": "A service was installed in the system. Service Name: %s" % name},
                    "eventdata": {"serviceName": name, "imagePath": p(path), "serviceType": kind,
                                  "startType": start, "accountName": "LocalSystem"}}}


# A recorded gateway line. The decoder's optional groups only line up when
# every field is present, so cases are built by substitution, not from scratch.
CEF = ("Oct 04 00:00:39 Home-CloudGateway CEF:0|Ubiquiti|UniFi Network|10.6.106|203|Blocked by Firewall|4|"
       "UNIFIcategory=Security UNIFIhost=Home-CloudGateway proto=TCP spt=47196 dpt=80 act=blocked app=HTTP "
       "UNIFIrisk=low UNIFIpolicyName=Trusted to Gateway Mgmt Block UNIFIpolicyType=Firewall UNIFIdirection=local "
       "deviceInboundInterface=Trusted UNIFIdstDeviceMac=74:f9:2c:dc:c9:c8 UNIFIdstDeviceName=Home-CloudGateway "
       "UNIFIdstDeviceModel=UCG-Fiber UNIFIdstDeviceIp=192.168.1.1 UNIFIdstDeviceVersion=5.1.33 "
       "UNIFIsrcClientAlias=Galaxy S25 Ultra UNIFIsrcClientHostname=Ben-s-S25-Ultra UNIFIsrcClientIp=192.168.20.91 "
       "UNIFIsrcClientMac=d0:56:fb:9c:c2:72 UNIFIsrcClientModel=Samsung Android Phone UNIFIsrcZone=Trusted "
       "UNIFIdstZone=Gateway UNIFIfirewallPolicy=Trusted to Gateway Mgmt Block UNIFItotalBytes=60 UNIFItotalPackets=1 "
       "UNIFIflowCount=1 UNIFIflowId=null UNIFIutcTime=2026-10-04T05:00:39.280Z "
       "msg=Galaxy S25 Ultra was blocked from accessing Home-CloudGateway by the Trusted to Gateway Mgmt Block Firewall Policy.")


def block(src, dport, src_zone="Trusted", dst_zone="Gateway", policy="Trusted to Gateway Mgmt Block",
          alias="Galaxy S25 Ultra"):
    return (CEF.replace("192.168.20.91", src).replace("dpt=80", "dpt=%s" % dport)
            .replace("Trusted to Gateway Mgmt Block", policy).replace("Galaxy S25 Ultra", alias)
            .replace("UNIFIsrcZone=Trusted", "UNIFIsrcZone=" + src_zone)
            .replace("UNIFIdstZone=Gateway", "UNIFIdstZone=" + dst_zone))


GITBASH = r"C:\Program Files\Git\bin\..\usr\bin\bash.exe"
SCRATCH = r"C:\Users\schug\AppData\Local\Temp\claude\C--Users-schug-src\8ff150cd-7d21-4d6e-8f7a-bb7f4b89a1cd\scratchpad"


DROPBOX = r"C:\Program Files\Dropbox\DropboxUpdater\123.0.6299.152\updater.exe"
GARMIN = r"C:\Program Files (x86)\Garmin\Express SelfUpdater\esu.exe"
OVERWOLF = r"C:\Program Files (x86)\Overwolf\0.311.0.6\Overwolf.exe"
SPOTIFY = r"C:\Program Files\WindowsApps\SpotifyAB.SpotifyMusic_1.303.264.0_x64__zpdnekdrzrea0\Spotify.exe"

CASES = [
    # 100240: trusted updaters, level 3
    ("Dropbox updater unpack in SystemTemp",
     sysmon11(DROPBOX, r"C:\Windows\SystemTemp\dropbox_Unpacker_BeginUnzipping9948_1127445525\app\274.4.4841\api-ms-win-core-file-l1-1-0.dll"),
     "100240", 3),
    ("Garmin esu assembly cache",
     sysmon11(GARMIN, r"C:\Windows\SysWOW64\config\systemprofile\AppData\Local\assembly\tmp\X5MEALU3\NLog.DLL"),
     "100240", 3),
    ("Garmin esu temp exe", sysmon11(GARMIN, r"C:\Windows\SystemTemp\tmp3B94.tmp.exe"), "100240", 3),
    ("Overwolf Widevine unpack in user Temp",
     sysmon11(OVERWOLF, r"C:\Users\schug\AppData\Local\Temp\chrome_Unpacker_BeginUnzipping34728_494299380\_platform_specific\win_x64\widevinecdm.dll",
              r"Ben-PC\schug"), "100240", 3),
    ("Spotify Widevine unpack in user Temp",
     sysmon11(SPOTIFY, r"C:\Users\schug\AppData\Local\Temp\chromium_chrome_Unpacker_BeginUnzipping41364_434891458\_platform_specific\win_x64\widevinecdm.dll",
              r"Ben-PC\schug"), "100240", 3),
    ("Dropbox updater writing elsewhere under Windows is NOT lowered",
     sysmon11(DROPBOX, r"C:\Windows\System32\evil.dll"), "92217", 6),
    ("Dropbox updater dropping into user Temp is NOT lowered",
     sysmon11(DROPBOX, r"C:\Users\schug\AppData\Local\Temp\payload.exe"), "92213", 15),
    ("Look-alike path outside Program Files is NOT lowered",
     sysmon11(r"C:\Users\schug\Dropbox\DropboxUpdater\1.0\updater.exe",
              r"C:\Windows\SystemTemp\dropbox_Unpacker_BeginUnzipping1_2\x.exe"), "92217", 6),
    ("Overwolf dropping a plain exe in Temp is NOT lowered",
     sysmon11(OVERWOLF, r"C:\Users\schug\AppData\Local\Temp\update.exe", r"Ben-PC\schug"), "92213", 15),
    # 100241: kernel mode drivers, level 12
    ("GIGABYTE kernel driver install",
     svc7045("GVCIDrv", r"C:\Program Files (x86)\GIGABYTE\RGBFusion\GVCIDrv64.sys", "kernel mode driver"), "100241", 12),
    ("AMD kernel driver install",
     svc7045("AMD Special Tools Driver", r"\SystemRoot\System32\drivers\AmdTools64.sys", "kernel mode driver"), "100241", 12),
    ("Sysmon driver install (boot start)",
     svc7045("SysmonDrv", r"C:\WINDOWS\SysmonDrv.sys", "kernel mode driver", "boot start"), "100241", 12),
    ("User mode service install stays level 5",
     svc7045("Docker Desktop Service", r"C:\Program Files\Docker\Docker\com.docker.service", "user mode service"), "61138", 5),
    ("Sysmon user mode service stays level 5",
     svc7045("Sysmon64", r"C:\WINDOWS\Sysmon64.exe", "user mode service", "auto start"), "61138", 5),
    # 100243: Claude Code session scratchpad, level 1
    ("Git bash writing a script into the Claude scratchpad",
     sysmon11(GITBASH, SCRATCH + r"\fix-wazuh-agent.ps1", r"Ben-PC\schug"), "100243", 1),
    ("Git bash (direct path) writing into the Claude scratchpad",
     sysmon11(r"C:\Program Files\Git\usr\bin\bash.exe", SCRATCH + r"\tools\probe.exe", r"Ben-PC\schug"), "100243", 1),
    ("claude.exe writing into the Claude scratchpad",
     sysmon11(r"C:\Users\schug\.local\bin\claude.exe", SCRATCH + r"\run.ps1", r"Ben-PC\schug"), "100243", 1),
    ("Git bash writing a script directly in Temp is NOT lowered",
     sysmon11(GITBASH, r"C:\Users\schug\AppData\Local\Temp\fix.ps1", r"Ben-PC\schug"), "92213", 15),
    ("Git bash writing outside the session folder is NOT lowered",
     sysmon11(GITBASH, r"C:\Users\schug\AppData\Local\Temp\claude\evil.exe", r"Ben-PC\schug"), "92213", 15),
    ("Unknown process writing into the Claude scratchpad is NOT lowered",
     sysmon11(r"C:\Users\schug\Downloads\setup.exe", SCRATCH + r"\drop.exe", r"Ben-PC\schug"), "92213", 15),
]

failed = 0
for name, event, want_id, want_level in CASES:
    got = ask(event)
    ok = got == (want_id, want_level)
    failed += not ok
    print("%-4s %-60s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("windows cases failed: %d of %d" % (failed, len(CASES)))

UNIFI = [
    ("Phone to gateway port 80", block("192.168.20.91", 80), "100242", 2),
    ("Phone to gateway port 443 stays level 5", block("192.168.20.91", 443), "100101", 5),
    ("Phone to external DoT stays level 5",
     block("192.168.20.91", 853, dst_zone="External", policy="Block DoT Trusted"), "100101", 5),
    ("Other Trusted client to gateway port 80 stays level 5", block("192.168.20.236", 80, alias="Other"), "100101", 5),
    ("Work client to gateway port 80 stays level 5",
     block("192.168.70.47", 80, src_zone="Work", policy="Work to Gateway Mgmt Block", alias="Work-PC"), "100101", 5),
]
failed2 = 0
for name, event, want_id, want_level in UNIFI:
    got = ask(event, "172.21.0.1")
    ok = got == (want_id, want_level)
    failed2 += not ok
    print("%-4s %-60s want %s L%s  got %s L%s" % ("ok" if ok else "FAIL", name, want_id, want_level, got[0], got[1]))
print("unifi cases failed: %d of %d" % (failed2, len(UNIFI)))
