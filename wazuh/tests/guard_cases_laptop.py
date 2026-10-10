"""Guard cases for the 2026-10-09 laptop triage (rules 100250 to 100261, and
the AnthropicClaude path added to 100215/100216).

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


SYSMON = {"providerName": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational",
          "severityValue": "INFORMATION"}
ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
REAL_GUID = "{e76878a6-5eb6-6ac8-a900-000000002800}"


def sysmon1(image, original, cmdline, parent, user=r"NT AUTHORITY\SYSTEM", parent_guid=REAL_GUID):
    ev = {"image": p(image), "originalFileName": original, "commandLine": p(cmdline), "user": p(user),
          "integrityLevel": "System", "processId": "1234", "parentProcessGuid": parent_guid}
    if parent is not None:
        ev["parentImage"] = p(parent)
    return {"win": {"system": dict(SYSMON, eventID="1"), "eventdata": ev}}


def sysmon11(image, target, user=r"Ben-Laptop\schug"):
    return {"win": {"system": dict(SYSMON, eventID="11"),
                    "eventdata": {"image": p(image), "targetFilename": p(target), "user": p(user),
                                  "processGuid": REAL_GUID}}}


def syslog(provider, event_id, message, eventdata=None, channel="System"):
    return {"win": {"system": {"providerName": provider, "eventID": str(event_id), "channel": channel,
                               "severityValue": "ERROR", "message": message},
                    "eventdata": eventdata or {}}}


def security(event_id, eventdata, message=""):
    return {"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "eventID": str(event_id),
                               "channel": "Security", "severityValue": "AUDIT_SUCCESS", "message": message},
                    "eventdata": eventdata}}


TEMP = r"C:\Users\schug\AppData\Local\Temp"
DSA_PKG = r"C:\ProgramData\Intel\DSA\Downloads\gfx_win_101.7092.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
BTH = r"C:\Windows\System32\backgroundTaskHost.exe"
DISCORD = r"C:\Users\schug\AppData\Local\Discord\app-1.0.9261\Discord.exe"
REG = r"C:\Windows\System32\reg.exe"
CMD = r"C:\Windows\System32\cmd.exe"
GUID = "{12077DBD-0371-4A51-BAE0-4FC6B176FB1C}"

CASES = [
    # 100250: Intel DSA installer chain
    ("DSA package unpacks a driver DLL into RarSFX0",
     sysmon11(DSA_PKG, TEMP + r"\RarSFX0\Graphics\igd10iumd64.dll"), "100250", 3),
    ("RarSFX0 Installer.exe stages a dependency",
     sysmon11(TEMP + r"\RarSFX0\Installer.exe", TEMP + r"\Intel\GFXInstaller\Installer_42013475\Dependencies\MainInstaller.exe"),
     "100250", 3),
    ("MainInstaller writes the next stage",
     sysmon11(TEMP + r"\Intel\GFXInstaller\Installer_42013475\Dependencies\MainInstaller.exe",
              TEMP + r"\Intel\GFXInstaller\Installer_42013475\Installer.exe"), "100250", 3),
    ("DSA-looking package writing outside RarSFX is NOT lowered",
     sysmon11(DSA_PKG, TEMP + r"\payload.exe"), "92213", 15),
    ("Unknown exe writing into RarSFX0 is NOT lowered",
     sysmon11(r"C:\Users\schug\Downloads\gfx_win_101.7092.exe", TEMP + r"\RarSFX0\Graphics\igd10iumd64.dll"), "92213", 15),
    ("RarSFX0 Installer.exe writing outside GFXInstaller is NOT lowered",
     sysmon11(TEMP + r"\RarSFX0\Installer.exe", TEMP + r"\svchost.exe"), "92213", 15),

    # 100251: WiX Burn stages
    ("Downloaded bundle copies itself to the clean room",
     sysmon11(r"C:\Users\schug\Downloads\aspnetcore-runtime-8.0.31-win-x86.exe",
              TEMP + r"\{9789F1F6-3E02-452F-AE90-7C6D53F958F9}\.cr\aspnetcore-runtime-8.0.31-win-x86.exe"), "100251", 3),
    ("Clean room copy writes the bootstrapper DLL",
     sysmon11(TEMP + r"\{9789F1F6-3E02-452F-AE90-7C6D53F958F9}\.cr\aspnetcore-runtime-8.0.31-win-x86.exe",
              TEMP + r"\{A5D9E846-3F57-4645-8800-BD2AA24FBE44}\.ba\wixstdba.dll"), "100251", 3),
    ("Package Cache bundle writes its engine to Windows\\Temp (92217)",
     sysmon11(r"C:\ProgramData\Package Cache\{FA1D428A-E075-4EC1-833B-E08B212DE158}\IntelGraphicsSoftwareInstaller.exe",
              r"C:\Windows\Temp\%s\.ba\wixstdba.dll" % GUID), "100251", 3),
    ("Intel extras bundle extracts a payload next to the clean room",
     sysmon11(TEMP + r"\RarSFX0\Resources\Extras\IntelGraphicsSoftware_26.32.2604.4_Release.exe",
              TEMP + r"\%s\install_prerequisites.cmd" % GUID), "100251", 3),
    ("Clean room copy writing outside the GUID folder is NOT lowered",
     sysmon11(TEMP + r"\%s\.cr\setup.exe" % GUID, TEMP + r"\dropper.exe"), "92213", 15),
    ("Downloaded exe writing a GUID folder without the Burn layout is NOT lowered",
     sysmon11(r"C:\Users\schug\Downloads\setup.exe", TEMP + r"\%s\sub\tool.exe" % GUID), "92213", 15),
    ("Unknown image writing into a clean room folder is NOT lowered",
     sysmon11(r"C:\Users\Public\setup.exe", TEMP + r"\%s\.cr\setup.exe" % GUID), "92213", 15),

    # 100252 / 100253: Sysmon lost the parent
    ("svchost with zero parent GUID and a service command line",
     sysmon1(SVCHOST, "svchost.exe", r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Winmgmt", None, parent_guid=ZERO_GUID),
     "100252", 3),
    ("per-user svchost with zero parent GUID",
     sysmon1(SVCHOST, "svchost.exe", r"C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService", None,
             user=r"Ben-Laptop\schug", parent_guid=ZERO_GUID), "100252", 3),
    ("svchost with a resolved unexpected parent is NOT lowered",
     sysmon1(SVCHOST, "svchost.exe", r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Winmgmt", r"C:\Users\schug\Downloads\x.exe"),
     "61618", 12),
    ("svchost with zero parent GUID but an odd command line is NOT lowered",
     sysmon1(SVCHOST, "svchost.exe", r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Winmgmt http://evil.example/x", None,
             parent_guid=ZERO_GUID), "61618", 12),
    ("svchost from a user folder with zero parent GUID is NOT lowered",
     sysmon1(r"C:\Users\schug\AppData\Local\Temp\svchost.exe", "svchost.exe",
             r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p", None, parent_guid=ZERO_GUID), "61618", 12),
    ("svchost with services.exe parent still takes the stock whitelist",
     sysmon1(SVCHOST, "svchost.exe", r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p", r"C:\Windows\System32\services.exe"),
     "61619", 0),
    ("backgroundTaskHost with zero parent GUID",
     sysmon1(BTH, "backgroundTaskHost.exe", r'"C:\WINDOWS\system32\backgroundTaskHost.exe" -ServerName:App.AppXapskvk16gk8da8kch5g4qxh42vxccved.mca',
             None, user=r"Ben-Laptop\schug", parent_guid=ZERO_GUID), "100253", 3),
    ("backgroundTaskHost with zero parent GUID and extra arguments is NOT lowered",
     sysmon1(BTH, "backgroundTaskHost.exe", r'"C:\WINDOWS\system32\backgroundTaskHost.exe" -ServerName:App.x.mca -Embedding evil',
             None, user=r"Ben-Laptop\schug", parent_guid=ZERO_GUID), "61634", 12),

    # 100254: DSATray opening its support page
    ("DSATray opens intel.com through explorer",
     sysmon1(r"C:\Windows\SysWOW64\explorer.exe", "EXPLORER.EXE",
             r'"C:\Windows\System32\explorer.exe" https://www.intel.com/content/www/us/en/support/intel-driver-support-assistant.html?updatenow&amp;fromnotif',
             r"C:\Program Files (x86)\Intel\Driver and Support Assistant\x86\DSATray.exe", user=r"Ben-Laptop\schug"), "100254", 3),
    ("DSATray opening a non-Intel URL is NOT lowered",
     sysmon1(r"C:\Windows\SysWOW64\explorer.exe", "EXPLORER.EXE", r'"C:\Windows\System32\explorer.exe" https://evil.example/',
             r"C:\Program Files (x86)\Intel\Driver and Support Assistant\x86\DSATray.exe", user=r"Ben-Laptop\schug"), "61640", 12),

    # 100255: Discord protocol handler
    ("Discord registers its URL protocol",
     sysmon1(REG, "reg.exe", r'C:\WINDOWS\System32\reg.exe add HKCU\Software\Classes\Discord /ve /d "URL:Discord Protocol" /f',
             DISCORD, user=r"Ben-Laptop\schug"), "100255", 3),
    ("Discord registers its open command",
     sysmon1(REG, "reg.exe", r'C:\WINDOWS\System32\reg.exe add HKCU\Software\Classes\Discord\shell\open\command /ve /d "\"%s\" --url -- \"%%1\"" /f' % DISCORD,
             DISCORD, user=r"Ben-Laptop\schug"), "100255", 3),
    ("Discord writing another Classes key is NOT lowered",
     sysmon1(REG, "reg.exe", r'C:\WINDOWS\System32\reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d "cmd.exe" /f',
             DISCORD, user=r"Ben-Laptop\schug"), "92041", 10),
    ("Discord look-alike outside AppData is NOT lowered",
     sysmon1(REG, "reg.exe", r'C:\WINDOWS\System32\reg.exe add HKCU\Software\Classes\Discord /ve /d "URL:Discord Protocol" /f',
             r"C:\Users\Public\Discord\app-1.0.9261\Discord.exe", user=r"Ben-Laptop\schug"), "92041", 10),

    # 100256: Start Menu shortcuts
    ("Claude updater refreshes its shortcut",
     sysmon11(r"C:\Users\schug\AppData\Local\AnthropicClaude\Update.exe",
              r"C:\Users\schug\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Anthropic\Claude.lnk"), "100256", 3),
    ("Discord refreshes its top-level shortcut",
     sysmon11(DISCORD, r"C:\Users\schug\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Discord.lnk"), "100256", 3),
    ("Discord writing a Startup folder shortcut is NOT lowered",
     sysmon11(DISCORD, r"C:\Users\schug\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Discord.lnk"), "92200", 6),
    ("Claude updater writing a differently named shortcut is NOT lowered",
     sysmon11(r"C:\Users\schug\AppData\Local\AnthropicClaude\Update.exe",
              r"C:\Users\schug\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Anthropic\Updater.lnk"), "92200", 6),

    # 100257 - 100259: helper shells
    ("Mullvad theme query",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /d /s /c "reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\ /v SystemUsesLightTheme"',
             r"C:\Program Files\Mullvad VPN\Mullvad VPN.exe", user=r"Ben-Laptop\schug"), "100257", 0),
    ("Mullvad running any other cmd is NOT lowered",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /d /s /c "whoami"',
             r"C:\Program Files\Mullvad VPN\Mullvad VPN.exe", user=r"Ben-Laptop\schug"), "92052", 4),
    ("Intel control panel service runs its batch file",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /c "C:\Intel\GfxCPLBatchFiles\{EC94D02F-D200-4428-9531-05AF7F9799CB}.bat"',
             r"C:\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_2ab7dcc8af555ba2\igfxCUIServiceN.exe"), "100258", 3),
    ("Intel control panel service running a batch from Temp is NOT lowered",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /c "C:\Users\schug\AppData\Local\Temp\x.bat"',
             r"C:\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_2ab7dcc8af555ba2\igfxCUIServiceN.exe"), "92052", 4),
    ("Wazuh restart active response stops the service",
     sysmon1(r"C:\Windows\SysWOW64\cmd.exe", "Cmd.Exe", r"C:\WINDOWS\system32\cmd.exe /c %%WINDIR%%\system32\net.exe stop Wazuh",
             r"C:\Program Files (x86)\ossec-agent\active-response\bin\restart-wazuh.exe"), "100259", 0),
    ("restart-wazuh running anything else is NOT lowered",
     sysmon1(r"C:\Windows\SysWOW64\cmd.exe", "Cmd.Exe", r"C:\WINDOWS\system32\cmd.exe /c net.exe stop WinDefend",
             r"C:\Program Files (x86)\ossec-agent\active-response\bin\restart-wazuh.exe"), "92052", 4),

    # 100215/100216: Claude desktop native host path
    ("Chrome launches the Claude desktop native host",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\Users\schug\AppData\Local\AnthropicClaude\app-2.31226.0\resources\chrome-native-host.exe" chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/ --parent-window=0" < \\.\pipe\chrome.nativeMessaging.in.7c855658bef89079 > \\.\pipe\chrome.nativeMessaging.out.7c855658bef89079',
             r"C:\Program Files\Google\Chrome\Application\chrome.exe", user=r"Ben-Laptop\schug"), "100215", 0),
    ("Chrome launching a native host from another folder is NOT lowered",
     sysmon1(CMD, "Cmd.Exe", r'C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\Users\schug\AppData\Local\Temp\chrome-native-host.exe" chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/"',
             r"C:\Program Files\Google\Chrome\Application\chrome.exe", user=r"Ben-Laptop\schug"), "92052", 4),

    # 100260: known broken services
    ("SCM timeout for the DSA service",
     syslog("Service Control Manager", 7009,
            "A timeout was reached (30000 milliseconds) while waiting for the Intel(R) Driver & Support Assistant service to connect.",
            {"param1": "30000", "param2": "Intel(R) Driver & Support Assistant"}), "100260", 3),
    ("SCM start failure for HASS.Agent",
     syslog("Service Control Manager", 7009,
            "A timeout was reached (30000 milliseconds) while waiting for the HASS.Agent - Satellite Service service to connect.",
            {"param1": "30000", "param2": "HASS.Agent - Satellite Service"}), "100260", 3),
    ("Store Spotify update failure",
     syslog("Microsoft-Windows-WindowsUpdateClient", 20,
            "Installation Failure: Windows failed to install the following update with error 0x80073D02: 9NCBCSZSJRSB-SpotifyAB.SpotifyMusic.",
            {"errorCode": "0x80073d02"}), "100260", 3),
    ("SCM timeout for another service is NOT lowered",
     syslog("Service Control Manager", 7009,
            "A timeout was reached (30000 milliseconds) while waiting for the Windows Defender Antivirus Service service to connect.",
            {"param1": "30000", "param2": "Windows Defender Antivirus Service"}), "61102", 5),
    ("Store failure for another app is NOT lowered",
     syslog("Microsoft-Windows-WindowsUpdateClient", 20,
            "Installation Failure: Windows failed to install the following update with error 0x80073D02: 9WZDNCRFJ3TJ-Microsoft.Office.",
            {"errorCode": "0x80073d02"}), "61102", 5),

    # 100261: W32Time clock sync
    ("Windows Time service adjusts the clock",
     security(4616, {"subjectUserSid": "S-1-5-19", "subjectUserName": "LOCAL SERVICE", "subjectDomainName": "NT AUTHORITY",
                     "processName": p(SVCHOST), "previousTime": "2026-10-09T02:55:40Z", "newTime": "2026-10-09T02:55:41Z"},
              "The system time was changed."), "100261", 3),
    ("User changing the clock is NOT lowered",
     security(4616, {"subjectUserSid": "S-1-5-21-1215267519-2342656075-4066380172-1001", "subjectUserName": "schug",
                     "subjectDomainName": "BEN-LAPTOP", "processName": p(r"C:\Windows\System32\SystemSettingsAdminFlows.exe"),
                     "previousTime": "2026-10-09T02:55:40Z", "newTime": "2026-10-09T05:55:41Z"},
              "The system time was changed."), "60132", 5),
]

fails = 0
for name, event, want_id, want_lvl in CASES:
    got_id, got_lvl = ask(event)
    ok = (got_id, got_lvl) == (want_id, want_lvl)
    fails += not ok
    print("%s  %-78s -> %s L%s%s" % ("PASS" if ok else "FAIL", name, got_id, got_lvl,
                                     "" if ok else "   (wanted %s L%s)" % (want_id, want_lvl)))
print("\n%d cases, %d failed" % (len(CASES), fails))
raise SystemExit(1 if fails else 0)
