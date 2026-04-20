/*
  Mal_scanner YARA Rules
  Author: Yx0R / Yash Gaikwad
  Version: 2.0.0
  
  Place custom rules here. Rules are reloaded each scan.
  See: https://yara.readthedocs.io/en/stable/
*/

rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "Yx0R / Yash Gaikwad"
        severity = "HIGH"
        reference = "Generic"
    strings:
        $enc1 = "powershell" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "-enc" nocase
        $b64  = /[A-Za-z0-9+\/]{50,}={0,2}/
    condition:
        ($enc1 and ($enc2 or $enc3)) or
        (filesize < 500KB and $b64)
}

rule Ransomware_File_Extensions {
    meta:
        description = "Ransomware ransom note or encrypted file pattern"
        author = "Yx0R / Yash Gaikwad"
        severity = "CRITICAL"
    strings:
        $r1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $r2 = "decrypt" nocase
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = ".locked" nocase
        $r6 = "READ_ME" nocase
        $r7 = "BTC" nocase
        $r8 = "Tor Browser" nocase
    condition:
        3 of them
}

rule Suspicious_PE_Imports {
    meta:
        description = "PE binary with suspicious import combination (injection/hollowing)"
        author = "Yx0R / Yash Gaikwad"
        severity = "MEDIUM"
    strings:
        $i1 = "VirtualAlloc" nocase
        $i2 = "CreateRemoteThread" nocase
        $i3 = "WriteProcessMemory" nocase
        $i4 = "OpenProcess" nocase
        $i5 = "LoadLibrary" nocase
        $i6 = "NtUnmapViewOfSection" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Webshell_Generic {
    meta:
        description = "Generic PHP/ASP webshell pattern"
        author = "Yx0R / Yash Gaikwad"
        severity = "HIGH"
    strings:
        $w1 = "eval($_POST"   nocase
        $w2 = "eval($_GET"    nocase
        $w3 = "eval(base64_decode" nocase
        $w4 = "system($_REQUEST" nocase
        $w5 = "passthru("     nocase
        $w6 = "shell_exec("   nocase
        $w7 = "assert($_POST" nocase
        $w8 = "preg_replace.*\/e" nocase
    condition:
        any of them
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger behavioral indicators via Win32 API"
        author = "Yx0R / Yash Gaikwad"
        severity = "HIGH"
    strings:
        $k1 = "GetAsyncKeyState" nocase
        $k2 = "SetWindowsHookEx" nocase
        $k3 = "GetForegroundWindow" nocase
        $k4 = "keylog" nocase
        $k5 = "keystroke" nocase
        $k6 = "WH_KEYBOARD" nocase
    condition:
        2 of them
}

rule Credential_Dumping {
    meta:
        description = "Credential dumping tool indicators"
        author = "Yx0R / Yash Gaikwad"
        severity = "CRITICAL"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "lsadump" nocase
        $m4 = "wdigest" nocase
        $m5 = "SamSs" nocase
        $m6 = "privilege::debug" nocase
    condition:
        any of them
}

rule Suspicious_Batch_Script {
    meta:
        description = "Malicious batch script patterns"
        author = "Yx0R / Yash Gaikwad"
        severity = "MEDIUM"
    strings:
        $b1 = "net user" nocase
        $b2 = "net localgroup administrators" nocase
        $b3 = "reg add" nocase
        $b4 = "schtasks /create" nocase
        $b5 = "wmic" nocase
        $b6 = "bitsadmin" nocase
        $b7 = "certutil -decode" nocase
    condition:
        3 of them
}

rule AntiDebug_Indicators {
    meta:
        description = "Anti-analysis / anti-debugging techniques"
        author = "Yx0R / Yash Gaikwad"
        severity = "MEDIUM"
    strings:
        $a1 = "IsDebuggerPresent" nocase
        $a2 = "CheckRemoteDebuggerPresent" nocase
        $a3 = "NtQueryInformationProcess" nocase
        $a4 = "OutputDebugString" nocase
        $a5 = "RDTSC" nocase
        $a6 = "timing check" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
