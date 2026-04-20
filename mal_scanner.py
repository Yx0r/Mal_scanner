#!/usr/bin/env python3
"""
Mal_scanner - Signature-Based Malware Detection Tool
Author: Yx0R / Yash Gaikwad
Version: 2.0.0
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import customtkinter as ctk
import hashlib
import os
import json
import threading
import time
import re
import struct
import sqlite3
import requests
import base64
import math
import zipfile
import tarfile
import datetime
import configparser
import subprocess
import sys
from pathlib import Path
from collections import defaultdict
import queue
import yara_x as yara
import pefile

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & PATHS
# ─────────────────────────────────────────────────────────────────────────────
APP_NAME    = "Mal_scanner"
APP_VERSION = "2.0.0"
APP_AUTHOR  = "Yx0R / Yash Gaikwad"

BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "mal_scanner_data"
DB_PATH     = DATA_DIR / "signatures.db"
CONFIG_PATH = DATA_DIR / "config.ini"
QUARANTINE  = DATA_DIR / "quarantine"
LOGS_DIR    = DATA_DIR / "logs"
YARA_DIR    = DATA_DIR / "yara_rules"

for d in [DATA_DIR, QUARANTINE, LOGS_DIR, YARA_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  BUILT-IN SIGNATURES (offline seed)
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_SIGNATURES = [
    # (name, hash_type, hash_value, threat_level, category, description)
    ("EICAR Test File", "md5", "44d88612fea8a8f36de82e1278abb02f", "LOW", "TEST", "EICAR antivirus test file"),
    ("EICAR Test File", "sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "LOW", "TEST", "EICAR antivirus test string SHA256"),
    ("WannaCry Ransomware", "md5", "84c82835a5d21bbcf75a61706d8ab549", "CRITICAL", "RANSOMWARE", "WannaCry ransomware dropper"),
    ("Mirai Botnet", "md5", "c45d5894ef75b1a7e62f73e2d7888e69", "HIGH", "BOTNET", "Mirai IoT botnet variant"),
    ("Emotet Loader", "sha256", "26b4699a7b9eeb16e76305d843d4738a6af1a3577191590ea76a2dc865d3e92a", "CRITICAL", "TROJAN", "Emotet banking trojan loader"),
    ("CobaltStrike Beacon", "md5", "73af35d56b6e0b3a993b82e2d4e44d78", "HIGH", "RAT", "CobaltStrike C2 beacon"),
    ("Ryuk Ransomware", "sha256", "8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b", "CRITICAL", "RANSOMWARE", "Ryuk ransomware"),
    ("Agent Tesla", "md5", "1d4b0dcb0a7e7d6de40a44a3d4a9e24a", "HIGH", "SPYWARE", "Agent Tesla keylogger/infostealer"),
    ("AsyncRAT", "sha256", "2f4e5b15b9d2c6a4f7e8d1c3a2b5f9e7d8c4a6b3e1f2d5c8a9b7e4f6c3d2a1b8", "HIGH", "RAT", "AsyncRAT remote access trojan"),
    ("RedLine Stealer", "md5", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "HIGH", "STEALER", "RedLine credential stealer"),
]

# ─────────────────────────────────────────────────────────────────────────────
#  SUSPICIOUS PATTERNS (byte-level heuristics)
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_STRINGS = [
    (rb"cmd\.exe\s*/c", "Shell command execution"),
    (rb"powershell\s+-[Ee][Nn][Cc]", "Encoded PowerShell"),
    (rb"VirtualAlloc", "Memory allocation (shellcode indicator)"),
    (rb"CreateRemoteThread", "Remote thread injection"),
    (rb"WriteProcessMemory", "Process memory writing"),
    (rb"IsDebuggerPresent", "Anti-debug check"),
    (rb"WScript\.Shell", "Windows scripting host abuse"),
    (rb"base64_decode", "Base64 decode (obfuscation)"),
    (rb"eval\(base64", "Eval with base64 (PHP webshell pattern)"),
    (rb"InternetOpenUrl", "HTTP request via WinInet"),
    (rb"RegSetValueEx", "Registry modification"),
    (rb"NtUnmapViewOfSection", "Process hollowing indicator"),
    (rb"RtlDecompressBuffer", "Runtime decompression"),
    (rb"mimikatz", "Credential dumping tool"),
    (rb"sekurlsa::", "Mimikatz command"),
    (rb"net user\s+.*\s+/add", "User account creation"),
    (rb"netsh\s+firewall", "Firewall manipulation"),
    (rb"schtasks\s+/create", "Scheduled task creation"),
    (rb"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Persistence via Run key"),
]

# ─────────────────────────────────────────────────────────────────────────────
#  DEFAULT YARA RULES
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_YARA_RULES = """
rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "Yx0R / Yash Gaikwad"
        severity = "HIGH"
    strings:
        $enc1 = "powershell" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "-enc" nocase
        $b64 = /[A-Za-z0-9+\\/]{50,}={0,2}/
    condition:
        ($enc1 and ($enc2 or $enc3)) or
        (filesize < 500KB and $b64)
}

rule Ransomware_File_Extensions {
    meta:
        description = "Ransomware ransom note or encrypted file list"
        severity = "CRITICAL"
    strings:
        $r1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $r2 = "decrypt" nocase
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = ".locked" nocase
        $r6 = "READ_ME" nocase
    condition:
        3 of them
}

rule Suspicious_PE_Imports {
    meta:
        description = "PE with suspicious import combination"
        severity = "MEDIUM"
    strings:
        $i1 = "VirtualAlloc" nocase
        $i2 = "CreateRemoteThread" nocase
        $i3 = "WriteProcessMemory" nocase
        $i4 = "OpenProcess" nocase
        $i5 = "LoadLibrary" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Webshell_Generic {
    meta:
        description = "Generic webshell pattern"
        severity = "HIGH"
    strings:
        $w1 = "eval($_POST" nocase
        $w2 = "eval($_GET" nocase
        $w3 = "eval(base64_decode" nocase
        $w4 = "system($_REQUEST" nocase
        $w5 = "passthru(" nocase
        $w6 = "shell_exec(" nocase
    condition:
        any of them
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger behavioral indicators"
        severity = "HIGH"
    strings:
        $k1 = "GetAsyncKeyState" nocase
        $k2 = "SetWindowsHookEx" nocase
        $k3 = "GetForegroundWindow" nocase
        $k4 = "keylog" nocase
        $k5 = "keystroke" nocase
    condition:
        2 of them
}
"""

# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
        self._seed_builtin()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS signatures (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                hash_type   TEXT NOT NULL,
                hash_value  TEXT NOT NULL UNIQUE,
                threat_level TEXT DEFAULT 'MEDIUM',
                category    TEXT DEFAULT 'MALWARE',
                description TEXT,
                source      TEXT DEFAULT 'local',
                added_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_path TEXT,
                files_scanned INTEGER,
                threats_found INTEGER,
                scan_duration REAL,
                scan_type   TEXT
            );

            CREATE TABLE IF NOT EXISTS threat_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER REFERENCES scan_history(id),
                file_path   TEXT,
                threat_name TEXT,
                threat_level TEXT,
                category    TEXT,
                detection_method TEXT,
                action_taken TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_hash ON signatures(hash_value);
            CREATE INDEX IF NOT EXISTS idx_scan ON threat_log(scan_id);
        """)
        conn.commit()
        conn.close()

    def _seed_builtin(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for sig in BUILTIN_SIGNATURES:
            try:
                c.execute("""INSERT OR IGNORE INTO signatures
                    (name, hash_type, hash_value, threat_level, category, description, source)
                    VALUES (?,?,?,?,?,?,'builtin')""", sig)
            except Exception:
                pass
        conn.commit()
        conn.close()

    def lookup_hash(self, hash_value: str) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT name,threat_level,category,description,source FROM signatures WHERE hash_value=?",
                  (hash_value.lower(),))
        row = c.fetchone()
        conn.close()
        if row:
            return {"name": row[0], "threat_level": row[1], "category": row[2],
                    "description": row[3], "source": row[4]}
        return None

    def add_signature(self, name, hash_type, hash_value, threat_level, category, description, source="user"):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("""INSERT OR REPLACE INTO signatures
                (name,hash_type,hash_value,threat_level,category,description,source)
                VALUES (?,?,?,?,?,?,?)""",
                (name, hash_type, hash_value.lower(), threat_level, category, description, source))
            conn.commit()
            return True
        except Exception as e:
            return False
        finally:
            conn.close()

    def get_stats(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM signatures")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM scan_history")
        scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM threat_log")
        threats = c.fetchone()[0]
        conn.close()
        return {"signatures": total, "scans": scans, "threats": threats}

    def save_scan(self, target, files, threats, duration, scan_type):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT INTO scan_history (target_path,files_scanned,threats_found,scan_duration,scan_type)
                     VALUES (?,?,?,?,?)""", (target, files, threats, duration, scan_type))
        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_threat(self, scan_id, file_path, threat_name, threat_level, category, method, action):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT INTO threat_log
            (scan_id,file_path,threat_name,threat_level,category,detection_method,action_taken)
            VALUES (?,?,?,?,?,?,?)""",
            (scan_id, file_path, threat_name, threat_level, category, method, action))
        conn.commit()
        conn.close()

    def get_scan_history(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""SELECT scan_date,target_path,files_scanned,threats_found,scan_duration,scan_type
                     FROM scan_history ORDER BY scan_date DESC LIMIT ?""", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def get_all_signatures(self, limit=500):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""SELECT name,hash_type,hash_value,threat_level,category,source,added_at
                     FROM signatures ORDER BY added_at DESC LIMIT ?""", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class ConfigManager:
    DEFAULTS = {
        "General": {
            "theme": "dark",
            "scan_threads": "4",
            "max_file_size_mb": "100",
            "auto_quarantine": "false",
            "show_notifications": "true",
        },
        "API": {
            "use_api": "false",
            "provider": "virustotal",
            "virustotal_key": "",
            "malwarebazaar_key": "",
            "api_timeout": "10",
            "api_rate_limit": "4",
        },
        "Heuristics": {
            "enable_heuristics": "true",
            "enable_yara": "true",
            "enable_pe_analysis": "true",
            "entropy_threshold": "7.2",
            "suspicious_string_check": "true",
        },
        "Logging": {
            "enable_logging": "true",
            "log_level": "INFO",
            "log_retention_days": "30",
        },
    }

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.cfg = configparser.ConfigParser()
        self._load()

    def _load(self):
        for section, values in self.DEFAULTS.items():
            if not self.cfg.has_section(section):
                self.cfg.add_section(section)
            for k, v in values.items():
                if not self.cfg.has_option(section, k):
                    self.cfg.set(section, k, v)
        if self.config_path.exists():
            self.cfg.read(self.config_path)
        self._save()

    def _save(self):
        with open(self.config_path, "w") as f:
            self.cfg.write(f)

    def get(self, section, key, fallback=None):
        return self.cfg.get(section, key, fallback=fallback)

    def getbool(self, section, key):
        return self.cfg.getboolean(section, key, fallback=False)

    def getint(self, section, key, fallback=0):
        return self.cfg.getint(section, key, fallback=fallback)

    def getfloat(self, section, key, fallback=0.0):
        return self.cfg.getfloat(section, key, fallback=fallback)

    def set(self, section, key, value):
        if not self.cfg.has_section(section):
            self.cfg.add_section(section)
        self.cfg.set(section, key, str(value))
        self._save()

# ─────────────────────────────────────────────────────────────────────────────
#  FILE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────
class FileAnalyzer:
    def __init__(self, cfg: ConfigManager, db: DatabaseManager):
        self.cfg = cfg
        self.db  = db
        self._load_yara()

    def _load_yara(self):
        self.yara_rules = None
        rules_file = YARA_DIR / "default.yar"
        if not rules_file.exists():
            rules_file.write_text(DEFAULT_YARA_RULES)
        try:
            self.yara_rules = yara.compile(filepath=str(rules_file))
        except Exception:
            try:
                # Compile inline
                self.yara_rules = yara.compile(source=DEFAULT_YARA_RULES)
            except Exception:
                self.yara_rules = None

    def compute_hashes(self, path: str) -> dict:
        hashes = {}
        try:
            data = Path(path).read_bytes()
            hashes["md5"]    = hashlib.md5(data).hexdigest()
            hashes["sha1"]   = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception:
            pass
        return hashes

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def check_signatures(self, hashes: dict) -> dict | None:
        for h_type in ("md5", "sha1", "sha256"):
            val = hashes.get(h_type)
            if val:
                result = self.db.lookup_hash(val)
                if result:
                    result["hash_type"] = h_type
                    result["hash_value"] = val
                    return result
        return None

    def check_suspicious_strings(self, data: bytes) -> list:
        findings = []
        for pattern, desc in SUSPICIOUS_STRINGS:
            if re.search(pattern, data, re.IGNORECASE):
                findings.append(desc)
        return findings

    def check_yara(self, path: str) -> list:
        matches = []
        if not self.yara_rules:
            return matches
        try:
            results = self.yara_rules.scan_file(path)
            for m in results.matching_rules:
                meta = {k: v for k, v in m.metadata}
                matches.append({
                    "rule": m.identifier,
                    "severity": meta.get("severity", "MEDIUM"),
                    "description": meta.get("description", "YARA rule match"),
                })
        except Exception:
            pass
        return matches

    def analyze_pe(self, path: str) -> dict:
        result = {"is_pe": False, "suspicious": [], "imports": [], "sections": []}
        try:
            pe = pefile.PE(path)
            result["is_pe"] = True
            # Check imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode(errors="ignore")
                            result["imports"].append(f"{dll}!{name}")
            # Check sections entropy
            for section in pe.sections:
                sec_name = section.Name.decode(errors="ignore").strip("\x00")
                data = section.get_data()
                ent = self.calculate_entropy(data)
                result["sections"].append({"name": sec_name, "entropy": ent, "size": len(data)})
                if ent > 7.2:
                    result["suspicious"].append(f"High entropy section '{sec_name}' ({ent:.2f}) – possible packing/encryption")
            # Suspicious flags
            susp_imports = {"VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                            "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState"}
            found = [i for i in result["imports"] if any(s in i for s in susp_imports)]
            if found:
                result["suspicious"].extend([f"Suspicious import: {f}" for f in found[:5]])
        except Exception:
            pass
        return result

    def analyze_file(self, path: str, use_api: bool = False, progress_cb=None) -> dict:
        result = {
            "path": path,
            "filename": os.path.basename(path),
            "size": 0,
            "status": "CLEAN",
            "threats": [],
            "hashes": {},
            "entropy": 0.0,
            "pe_info": {},
            "yara_matches": [],
            "suspicious_strings": [],
            "api_result": None,
            "scan_time": 0.0,
        }

        t0 = time.time()

        try:
            stat = os.stat(path)
            result["size"] = stat.st_size
            max_mb = self.cfg.getint("General", "max_file_size_mb", 100)
            if result["size"] > max_mb * 1024 * 1024:
                result["status"] = "SKIPPED"
                result["threats"].append({"name": "File too large", "level": "INFO", "method": "size_check"})
                return result

            data = Path(path).read_bytes()
            result["entropy"] = self.calculate_entropy(data)
            result["hashes"]  = self.compute_hashes(path)

            if progress_cb: progress_cb(20)

            # Signature check
            sig = self.check_signatures(result["hashes"])
            if sig:
                result["status"] = "THREAT"
                result["threats"].append({
                    "name": sig["name"],
                    "level": sig["threat_level"],
                    "category": sig.get("category", "MALWARE"),
                    "description": sig.get("description", ""),
                    "method": "signature",
                })

            if progress_cb: progress_cb(40)

            # YARA
            if self.cfg.getbool("Heuristics", "enable_yara"):
                yara_hits = self.check_yara(path)
                result["yara_matches"] = yara_hits
                for hit in yara_hits:
                    result["status"] = "THREAT"
                    result["threats"].append({
                        "name": hit["rule"],
                        "level": hit["severity"],
                        "category": "YARA",
                        "description": hit["description"],
                        "method": "yara",
                    })

            if progress_cb: progress_cb(60)

            # PE analysis
            if self.cfg.getbool("Heuristics", "enable_pe_analysis"):
                pe_info = self.analyze_pe(path)
                result["pe_info"] = pe_info
                for susp in pe_info.get("suspicious", []):
                    if result["status"] == "CLEAN":
                        result["status"] = "SUSPICIOUS"
                    result["threats"].append({
                        "name": "PE Heuristic",
                        "level": "MEDIUM",
                        "category": "HEURISTIC",
                        "description": susp,
                        "method": "pe_analysis",
                    })

            if progress_cb: progress_cb(75)

            # String heuristics
            if self.cfg.getbool("Heuristics", "suspicious_string_check"):
                ss = self.check_suspicious_strings(data)
                result["suspicious_strings"] = ss
                if ss and result["status"] == "CLEAN":
                    result["status"] = "SUSPICIOUS"

            # Entropy heuristic
            threshold = self.cfg.getfloat("Heuristics", "entropy_threshold", 7.2)
            if result["entropy"] > threshold and result["status"] == "CLEAN":
                result["status"] = "SUSPICIOUS"
                result["threats"].append({
                    "name": "High Entropy",
                    "level": "LOW",
                    "category": "HEURISTIC",
                    "description": f"File entropy {result['entropy']:.2f} exceeds threshold {threshold} – possible packing",
                    "method": "entropy",
                })

            if progress_cb: progress_cb(90)

            # API lookup
            if use_api and self.cfg.getbool("API", "use_api"):
                api_result = self._api_lookup(result["hashes"].get("sha256", ""))
                result["api_result"] = api_result
                if api_result and api_result.get("malicious"):
                    result["status"] = "THREAT"
                    result["threats"].append({
                        "name": api_result.get("name", "API Detection"),
                        "level": "HIGH",
                        "category": "API",
                        "description": f"Detected by {api_result.get('engine_count', '?')} engines via {api_result.get('source','')}",
                        "method": "api",
                    })

            if progress_cb: progress_cb(100)

        except PermissionError:
            result["status"] = "ERROR"
            result["threats"].append({"name": "Access Denied", "level": "INFO", "method": "io"})
        except Exception as e:
            result["status"] = "ERROR"
            result["threats"].append({"name": f"Error: {e}", "level": "INFO", "method": "io"})

        result["scan_time"] = round(time.time() - t0, 3)
        return result

    def _api_lookup(self, sha256: str) -> dict | None:
        if not sha256:
            return None
        provider = self.cfg.get("API", "provider", "virustotal")
        timeout  = self.cfg.getint("API", "api_timeout", 10)
        try:
            if provider == "virustotal":
                key = self.cfg.get("API", "virustotal_key", "")
                if not key:
                    return None
                url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                r = requests.get(url, headers={"x-apikey": key}, timeout=timeout)
                if r.status_code == 200:
                    data = r.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    mal   = stats.get("malicious", 0)
                    total = sum(stats.values())
                    name  = ""
                    names = data["data"]["attributes"].get("names", [])
                    if names:
                        name = names[0]
                    return {
                        "malicious": mal > 0,
                        "engine_count": f"{mal}/{total}",
                        "name": name,
                        "source": "VirusTotal",
                    }
            elif provider == "malwarebazaar":
                url = "https://mb-api.abuse.ch/api/v1/"
                r = requests.post(url, data={"query": "get_info", "hash": sha256}, timeout=timeout)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("query_status") == "ok":
                        entry = data["data"][0]
                        return {
                            "malicious": True,
                            "engine_count": "MalwareBazaar",
                            "name": entry.get("file_name", ""),
                            "source": "MalwareBazaar",
                        }
        except Exception:
            pass
        return None

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────────────────────────────────────
class AppLogger:
    def __init__(self, cfg: ConfigManager):
        self.cfg = cfg
        self.log_file = LOGS_DIR / f"mal_scanner_{datetime.date.today()}.log"

    def log(self, level: str, message: str):
        if not self.cfg.getbool("Logging", "enable_logging"):
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {message}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(line)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  QUARANTINE MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class QuarantineManager:
    def quarantine(self, file_path: str) -> bool:
        try:
            src = Path(file_path)
            dest = QUARANTINE / (src.name + ".quar")
            # Read, base64-encode to neutralize
            data = src.read_bytes()
            encoded = base64.b64encode(data)
            dest.write_bytes(encoded)
            # Overwrite original with zeros then delete
            src.write_bytes(b"\x00" * len(data))
            src.unlink()
            meta = {
                "original_path": str(src),
                "quarantined_at": datetime.datetime.now().isoformat(),
                "original_size": len(data),
            }
            (QUARANTINE / (src.name + ".meta")).write_text(json.dumps(meta, indent=2))
            return True
        except Exception:
            return False

    def restore(self, quar_file: str) -> bool:
        try:
            qpath = Path(quar_file)
            meta_path = Path(str(quar_file).replace(".quar", ".meta"))
            meta = json.loads(meta_path.read_text())
            encoded = qpath.read_bytes()
            data = base64.b64decode(encoded)
            Path(meta["original_path"]).write_bytes(data)
            qpath.unlink()
            meta_path.unlink()
            return True
        except Exception:
            return False

    def list_quarantined(self):
        items = []
        for f in QUARANTINE.glob("*.meta"):
            try:
                meta = json.loads(f.read_text())
                items.append(meta)
            except Exception:
                pass
        return items

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN GUI APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class MalScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # ── Core services ──────────────────────────────────────────────────
        self.cfg        = ConfigManager(CONFIG_PATH)
        self.db         = DatabaseManager(DB_PATH)
        self.analyzer   = FileAnalyzer(self.cfg, self.db)
        self.quarantine = QuarantineManager()
        self.logger     = AppLogger(self.cfg)
        self.scan_queue = queue.Queue()
        self._scanning  = False
        self._scan_results = []

        # ── Window ─────────────────────────────────────────────────────────
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title(f"{APP_NAME} v{APP_VERSION}  •  by {APP_AUTHOR}")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(fg_color="#0A0E1A")

        self._build_ui()
        self._update_stats()
        self.logger.log("INFO", "Mal_scanner started")

    # ──────────────────────────────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ──────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Left sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, fg_color="#0D1225", corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo area
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="#111830", corner_radius=0, height=100)
        logo_frame.pack(fill="x")
        ctk.CTkLabel(logo_frame, text="🔬", font=("", 36)).pack(pady=(14, 0))
        ctk.CTkLabel(logo_frame, text=APP_NAME, font=ctk.CTkFont("Courier New", 20, "bold"),
                     text_color="#00F5FF").pack()
        ctk.CTkLabel(logo_frame, text=f"v{APP_VERSION}", font=ctk.CTkFont("Courier New", 10),
                     text_color="#445577").pack(pady=(0, 12))

        # Nav buttons
        self.nav_btns = {}
        nav_items = [
            ("🎯 Scanner",    "scanner"),
            ("📊 Dashboard",  "dashboard"),
            ("📜 History",    "history"),
            ("🧬 Signatures", "signatures"),
            ("🔒 Quarantine", "quarantine"),
            ("⚙️ Settings",   "settings"),
            ("📋 Logs",       "logs"),
        ]
        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, pady=10)

        for label, key in nav_items:
            btn = ctk.CTkButton(
                nav_frame, text=label, anchor="w", width=200,
                font=ctk.CTkFont("Courier New", 13),
                fg_color="transparent", hover_color="#1A2545",
                text_color="#8899BB", corner_radius=6,
                command=lambda k=key: self._switch_page(k)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_btns[key] = btn

        # Author badge
        ctk.CTkLabel(self.sidebar, text=f"⚡ {APP_AUTHOR}",
                     font=ctk.CTkFont("Courier New", 10),
                     text_color="#334466").pack(side="bottom", pady=10)

        # Main content
        self.content = ctk.CTkFrame(self, fg_color="#0A0E1A", corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)

        # Build pages
        self.pages = {}
        self._build_scanner_page()
        self._build_dashboard_page()
        self._build_history_page()
        self._build_signatures_page()
        self._build_quarantine_page()
        self._build_settings_page()
        self._build_logs_page()

        self._switch_page("scanner")

    def _switch_page(self, key: str):
        for k, frame in self.pages.items():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True)

        for k, btn in self.nav_btns.items():
            if k == key:
                btn.configure(fg_color="#132040", text_color="#00F5FF")
            else:
                btn.configure(fg_color="transparent", text_color="#8899BB")

        if key == "history":    self._refresh_history()
        if key == "signatures": self._refresh_signatures()
        if key == "quarantine": self._refresh_quarantine()
        if key == "logs":       self._refresh_logs()
        if key == "dashboard":  self._refresh_dashboard()

    # ── SCANNER PAGE ────────────────────────────────────────────────────────
    def _build_scanner_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["scanner"] = page

        # Header
        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="🎯  THREAT SCANNER", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)
        self._stat_label = ctk.CTkLabel(hdr, text="", font=ctk.CTkFont("Courier New", 11),
                                         text_color="#445566")
        self._stat_label.pack(side="right", padx=20)

        # Scan controls
        ctrl = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        ctrl.pack(fill="x", padx=20, pady=(15, 5))

        # Scan type
        type_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        type_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(type_frame, text="SCAN TYPE", font=ctk.CTkFont("Courier New", 11, "bold"),
                     text_color="#445577").pack(side="left")

        self.scan_type = ctk.StringVar(value="file")
        for label, val in [("File", "file"), ("Directory", "dir"), ("Quick", "quick"), ("Full System", "full")]:
            ctk.CTkRadioButton(type_frame, text=label, variable=self.scan_type, value=val,
                               font=ctk.CTkFont("Courier New", 12),
                               text_color="#AABBCC", border_color="#00F5FF",
                               fg_color="#00F5FF").pack(side="left", padx=15)

        # Target path
        path_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        path_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.target_entry = ctk.CTkEntry(path_frame, placeholder_text="Target path…",
                                          font=ctk.CTkFont("Courier New", 12),
                                          fg_color="#080D1A", border_color="#1A3050",
                                          text_color="#CCDDEF", height=38)
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(path_frame, text="Browse", width=90, height=38,
                      font=ctk.CTkFont("Courier New", 12),
                      fg_color="#0A2040", hover_color="#1A4070",
                      command=self._browse_target).pack(side="left", padx=(0, 8))

        # API toggle
        self.use_api_scan = ctk.BooleanVar(value=self.cfg.getbool("API", "use_api"))
        ctk.CTkCheckBox(path_frame, text="Use API", variable=self.use_api_scan,
                        font=ctk.CTkFont("Courier New", 12), text_color="#AABBCC",
                        fg_color="#00F5FF", border_color="#225566").pack(side="left", padx=8)

        # Scan button
        self.scan_btn = ctk.CTkButton(ctrl, text="▶  START SCAN", height=44,
                                       font=ctk.CTkFont("Courier New", 15, "bold"),
                                       fg_color="#003355", hover_color="#004477",
                                       text_color="#00F5FF", corner_radius=8,
                                       command=self._start_scan)
        self.scan_btn.pack(padx=20, pady=(0, 12), fill="x")

        # Progress
        self.progress_bar = ctk.CTkProgressBar(page, height=6, fg_color="#0D1225",
                                                progress_color="#00F5FF")
        self.progress_bar.pack(fill="x", padx=20, pady=(5, 0))
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(page, text="Ready to scan",
                                            font=ctk.CTkFont("Courier New", 11),
                                            text_color="#445566")
        self.progress_label.pack(anchor="w", padx=22)

        # Results area
        results_frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Results header
        rh = ctk.CTkFrame(results_frame, fg_color="transparent")
        rh.pack(fill="x", padx=15, pady=(10, 5))
        ctk.CTkLabel(rh, text="SCAN RESULTS", font=ctk.CTkFont("Courier New", 12, "bold"),
                     text_color="#445577").pack(side="left")
        self.result_summary = ctk.CTkLabel(rh, text="",
                                            font=ctk.CTkFont("Courier New", 11),
                                            text_color="#00F5FF")
        self.result_summary.pack(side="left", padx=15)
        ctk.CTkButton(rh, text="Export Report", width=110, height=30,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#0A2030", hover_color="#1A3040",
                      command=self._export_report).pack(side="right")
        ctk.CTkButton(rh, text="Clear", width=70, height=30,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#200A0A", hover_color="#401010",
                      command=self._clear_results).pack(side="right", padx=(0, 6))

        # Treeview
        tree_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Scan.Treeview", background="#080D1A", foreground="#AABBCC",
                        fieldbackground="#080D1A", font=("Courier New", 11),
                        rowheight=26)
        style.configure("Scan.Treeview.Heading", background="#0D1830", foreground="#00F5FF",
                        font=("Courier New", 11, "bold"), relief="flat")
        style.map("Scan.Treeview", background=[("selected", "#132040")])

        cols = ("status", "filename", "threat", "level", "method", "size", "entropy")
        self.result_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                         style="Scan.Treeview")
        col_cfg = {
            "status":   ("Status",      80),
            "filename": ("File",        280),
            "threat":   ("Threat Name", 200),
            "level":    ("Level",       90),
            "method":   ("Detection",   100),
            "size":     ("Size",        80),
            "entropy":  ("Entropy",     70),
        }
        for col, (heading, width) in col_cfg.items():
            self.result_tree.heading(col, text=heading)
            self.result_tree.column(col, width=width, minwidth=50)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=vsb.set)
        self.result_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Tag colors
        self.result_tree.tag_configure("THREAT",    foreground="#FF4444", background="#1A0808")
        self.result_tree.tag_configure("SUSPICIOUS", foreground="#FFAA00", background="#1A1000")
        self.result_tree.tag_configure("CLEAN",     foreground="#44FF88", background="#081208")
        self.result_tree.tag_configure("ERROR",     foreground="#888888")
        self.result_tree.tag_configure("SKIPPED",   foreground="#556677")

        self.result_tree.bind("<Double-1>", self._show_file_detail)

        # Action buttons
        act = ctk.CTkFrame(results_frame, fg_color="transparent")
        act.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(act, text="🔒 Quarantine Selected", height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#200A0A", hover_color="#401010",
                      command=self._quarantine_selected).pack(side="left", padx=(0, 8))
        ctk.CTkButton(act, text="🗑 Delete Selected", height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#200808", hover_color="#501010",
                      command=self._delete_selected).pack(side="left")

    # ── DASHBOARD PAGE ──────────────────────────────────────────────────────
    def _build_dashboard_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["dashboard"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="📊  DASHBOARD", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)

        # Stats cards
        cards_frame = ctk.CTkFrame(page, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=15)

        self.dash_cards = {}
        cards = [
            ("signatures", "🧬", "Signatures", "#00F5FF"),
            ("scans",      "🔍", "Total Scans", "#44FF88"),
            ("threats",    "⚠️",  "Threats Found", "#FF4444"),
            ("quarantine", "🔒", "Quarantined",  "#FFAA00"),
        ]
        for key, icon, label, color in cards:
            card = ctk.CTkFrame(cards_frame, fg_color="#0D1225", corner_radius=12)
            card.pack(side="left", fill="x", expand=True, padx=8)
            ctk.CTkLabel(card, text=icon, font=("", 28)).pack(pady=(16, 4))
            val_lbl = ctk.CTkLabel(card, text="–", font=ctk.CTkFont("Courier New", 28, "bold"),
                                    text_color=color)
            val_lbl.pack()
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont("Courier New", 11),
                         text_color="#445566").pack(pady=(0, 16))
            self.dash_cards[key] = val_lbl

        # Recent threats
        rt_frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        rt_frame.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        ctk.CTkLabel(rt_frame, text="RECENT THREATS", font=ctk.CTkFont("Courier New", 12, "bold"),
                     text_color="#445577").pack(anchor="w", padx=15, pady=(12, 6))

        self.recent_text = ctk.CTkTextbox(rt_frame, fg_color="#080D1A", text_color="#AABBCC",
                                           font=ctk.CTkFont("Courier New", 11),
                                           border_width=0)
        self.recent_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _refresh_dashboard(self):
        stats = self.db.get_stats()
        self.dash_cards["signatures"].configure(text=str(stats["signatures"]))
        self.dash_cards["scans"].configure(text=str(stats["scans"]))
        self.dash_cards["threats"].configure(text=str(stats["threats"]))
        self.dash_cards["quarantine"].configure(text=str(len(self.quarantine.list_quarantined())))

        self.recent_text.configure(state="normal")
        self.recent_text.delete("0.0", "end")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""SELECT detected_at,file_path,threat_name,threat_level,category
                     FROM threat_log ORDER BY detected_at DESC LIMIT 20""")
        rows = c.fetchall()
        conn.close()
        if not rows:
            self.recent_text.insert("end", "  No threats recorded yet.\n", "clean")
        for row in rows:
            ts, fp, name, level, cat = row
            self.recent_text.insert("end", f"  [{ts}] ", "dim")
            self.recent_text.insert("end", f"[{level}] ", "level")
            self.recent_text.insert("end", f"{name} ", "name")
            self.recent_text.insert("end", f"→ {Path(fp).name}\n", "path")
        self.recent_text.configure(state="disabled")

    # ── HISTORY PAGE ────────────────────────────────────────────────────────
    def _build_history_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["history"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="📜  SCAN HISTORY", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)

        frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        cols = ("date", "target", "files", "threats", "duration", "type")
        self.history_tree = ttk.Treeview(frame, columns=cols, show="headings", style="Scan.Treeview")
        cfg = {"date": ("Date", 160), "target": ("Target", 300), "files": ("Files Scanned", 110),
               "threats": ("Threats", 80), "duration": ("Duration(s)", 90), "type": ("Type", 90)}
        for col, (h, w) in cfg.items():
            self.history_tree.heading(col, text=h)
            self.history_tree.column(col, width=w)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=vsb.set)
        self.history_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        vsb.pack(side="right", fill="y", pady=10, padx=(0, 5))

    def _refresh_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        for row in self.db.get_scan_history():
            tag = "threat" if row[3] > 0 else "clean"
            self.history_tree.insert("", "end", values=row,
                                      tags=(tag,))
        self.history_tree.tag_configure("threat", foreground="#FF6644")
        self.history_tree.tag_configure("clean",  foreground="#44FF88")

    # ── SIGNATURES PAGE ─────────────────────────────────────────────────────
    def _build_signatures_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["signatures"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="🧬  SIGNATURE DATABASE", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)

        # Add signature panel
        add_frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        add_frame.pack(fill="x", padx=20, pady=(15, 5))
        ctk.CTkLabel(add_frame, text="ADD SIGNATURE", font=ctk.CTkFont("Courier New", 11, "bold"),
                     text_color="#445577").pack(anchor="w", padx=15, pady=(10, 6))

        row1 = ctk.CTkFrame(add_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(0, 6))
        self.sig_name  = ctk.CTkEntry(row1, placeholder_text="Name", width=180,
                                       font=ctk.CTkFont("Courier New", 11),
                                       fg_color="#080D1A", border_color="#1A3050", text_color="#CCDDEF")
        self.sig_hash  = ctk.CTkEntry(row1, placeholder_text="Hash value (md5/sha256)",
                                       font=ctk.CTkFont("Courier New", 11),
                                       fg_color="#080D1A", border_color="#1A3050", text_color="#CCDDEF")
        self.sig_htype = ctk.CTkOptionMenu(row1, values=["md5", "sha1", "sha256"], width=90,
                                            font=ctk.CTkFont("Courier New", 11),
                                            fg_color="#0A2040", button_color="#0A2040",
                                            text_color="#AABBCC")
        self.sig_level = ctk.CTkOptionMenu(row1, values=["LOW", "MEDIUM", "HIGH", "CRITICAL"], width=100,
                                            font=ctk.CTkFont("Courier New", 11),
                                            fg_color="#0A2040", button_color="#0A2040",
                                            text_color="#AABBCC")
        self.sig_cat   = ctk.CTkEntry(row1, placeholder_text="Category", width=120,
                                       font=ctk.CTkFont("Courier New", 11),
                                       fg_color="#080D1A", border_color="#1A3050", text_color="#CCDDEF")
        for w in [self.sig_name, self.sig_hash, self.sig_htype, self.sig_level, self.sig_cat]:
            w.pack(side="left", padx=4, ipady=4)

        ctk.CTkButton(row1, text="+ Add", width=80, height=36,
                      font=ctk.CTkFont("Courier New", 12, "bold"),
                      fg_color="#003355", hover_color="#004477",
                      command=self._add_signature).pack(side="left", padx=8)

        # Import/update buttons
        row2 = ctk.CTkFrame(add_frame, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=(0, 12))
        ctk.CTkButton(row2, text="📥 Import CSV", width=120, height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#0A2030", hover_color="#1A3040",
                      command=self._import_sigs_csv).pack(side="left", padx=(0, 8))
        ctk.CTkButton(row2, text="🌐 Fetch from API", width=140, height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#0A2030", hover_color="#1A3040",
                      command=self._fetch_sigs_api).pack(side="left")

        # Table
        sig_tbl = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        sig_tbl.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        cols = ("name", "hash_type", "hash_value", "level", "category", "source", "added")
        self.sig_tree = ttk.Treeview(sig_tbl, columns=cols, show="headings", style="Scan.Treeview")
        cfg = {"name": ("Name", 180), "hash_type": ("Type", 60), "hash_value": ("Hash", 280),
               "level": ("Level", 80), "category": ("Category", 100), "source": ("Source", 80),
               "added": ("Added", 140)}
        for col, (h, w) in cfg.items():
            self.sig_tree.heading(col, text=h)
            self.sig_tree.column(col, width=w)

        vsb = ttk.Scrollbar(sig_tbl, orient="vertical", command=self.sig_tree.yview)
        self.sig_tree.configure(yscrollcommand=vsb.set)
        self.sig_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        vsb.pack(side="right", fill="y", pady=10, padx=(0, 5))

    def _refresh_signatures(self):
        for item in self.sig_tree.get_children():
            self.sig_tree.delete(item)
        for row in self.db.get_all_signatures():
            name, htype, hval, level, cat, src, added = row
            tag = level.lower() if level else "medium"
            self.sig_tree.insert("", "end", values=row, tags=(tag,))
        self.sig_tree.tag_configure("critical", foreground="#FF2222")
        self.sig_tree.tag_configure("high",     foreground="#FF8800")
        self.sig_tree.tag_configure("medium",   foreground="#FFDD00")
        self.sig_tree.tag_configure("low",      foreground="#44AAFF")

    def _add_signature(self):
        name  = self.sig_name.get().strip()
        hval  = self.sig_hash.get().strip()
        htype = self.sig_htype.get()
        level = self.sig_level.get()
        cat   = self.sig_cat.get().strip() or "MALWARE"
        if not name or not hval:
            messagebox.showwarning("Input Error", "Name and hash value are required.")
            return
        if self.db.add_signature(name, htype, hval, level, cat, "", "user"):
            messagebox.showinfo("Added", f"Signature '{name}' added successfully.")
            self._refresh_signatures()
        else:
            messagebox.showerror("Error", "Failed to add (duplicate hash?).")

    def _import_sigs_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All", "*.*")])
        if not path:
            return
        count = 0
        try:
            with open(path, newline="") as f:
                import csv
                reader = csv.DictReader(f)
                for row in reader:
                    self.db.add_signature(
                        row.get("name","Unknown"),
                        row.get("hash_type","md5"),
                        row.get("hash_value",""),
                        row.get("threat_level","MEDIUM"),
                        row.get("category","MALWARE"),
                        row.get("description",""),
                        "csv_import"
                    )
                    count += 1
            messagebox.showinfo("Import", f"Imported {count} signatures.")
            self._refresh_signatures()
        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    def _fetch_sigs_api(self):
        if not self.cfg.getbool("API", "use_api"):
            messagebox.showinfo("API Disabled", "Enable API in Settings first.")
            return
        provider = self.cfg.get("API", "provider")
        messagebox.showinfo("Fetch", f"Fetching signatures from {provider}…\n(Demo: adds sample updated signatures)")
        # Demo: in production, query MalwareBazaar's recent signatures
        self.db.add_signature("MalwareBazaar Demo", "sha256",
                              "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                              "HIGH", "TROJAN", "Demo API fetch entry", "api")
        self._refresh_signatures()

    # ── QUARANTINE PAGE ─────────────────────────────────────────────────────
    def _build_quarantine_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["quarantine"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="🔒  QUARANTINE VAULT", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)

        frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        # Buttons
        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btns, text="♻️ Restore Selected", height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#0A2030", hover_color="#1A3040",
                      command=self._restore_quarantined).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="🗑 Delete Permanently", height=32,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#200A0A", hover_color="#401010",
                      command=self._delete_quarantined).pack(side="left")

        cols = ("name", "original", "quarantined", "size")
        self.quar_tree = ttk.Treeview(frame, columns=cols, show="headings", style="Scan.Treeview")
        cfg = {"name": ("File", 200), "original": ("Original Path", 350),
               "quarantined": ("Quarantined At", 160), "size": ("Size (bytes)", 100)}
        for col, (h, w) in cfg.items():
            self.quar_tree.heading(col, text=h)
            self.quar_tree.column(col, width=w)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.quar_tree.yview)
        self.quar_tree.configure(yscrollcommand=vsb.set)
        self.quar_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        vsb.pack(side="right", fill="y", pady=(0, 10), padx=(0, 5))

    def _refresh_quarantine(self):
        for item in self.quar_tree.get_children():
            self.quar_tree.delete(item)
        for meta in self.quarantine.list_quarantined():
            orig = meta.get("original_path", "")
            name = Path(orig).name
            ts   = meta.get("quarantined_at", "")
            size = meta.get("original_size", 0)
            self.quar_tree.insert("", "end", values=(name, orig, ts, size),
                                   tags=("quar",))
        self.quar_tree.tag_configure("quar", foreground="#FFAA00")

    def _restore_quarantined(self):
        sel = self.quar_tree.selection()
        if not sel:
            return
        item = self.quar_tree.item(sel[0])["values"]
        orig = item[1]
        quar_file = str(QUARANTINE / (Path(orig).name + ".quar"))
        if self.quarantine.restore(quar_file):
            messagebox.showinfo("Restored", f"File restored to:\n{orig}")
        else:
            messagebox.showerror("Error", "Could not restore file.")
        self._refresh_quarantine()

    def _delete_quarantined(self):
        sel = self.quar_tree.selection()
        if not sel:
            return
        item = self.quar_tree.item(sel[0])["values"]
        orig = item[1]
        quar_file = QUARANTINE / (Path(orig).name + ".quar")
        meta_file = QUARANTINE / (Path(orig).name + ".meta")
        for f in [quar_file, meta_file]:
            if f.exists():
                f.unlink()
        messagebox.showinfo("Deleted", "Quarantined file permanently deleted.")
        self._refresh_quarantine()

    # ── SETTINGS PAGE ───────────────────────────────────────────────────────
    def _build_settings_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["settings"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="⚙️  SETTINGS", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)

        scroll = ctk.CTkScrollableFrame(page, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=15)

        def section(title):
            f = ctk.CTkFrame(scroll, fg_color="#0D1225", corner_radius=12)
            f.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(f, text=title, font=ctk.CTkFont("Courier New", 12, "bold"),
                         text_color="#00F5FF").pack(anchor="w", padx=15, pady=(12, 6))
            return f

        def row(parent, label, widget_builder):
            r = ctk.CTkFrame(parent, fg_color="transparent")
            r.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(r, text=label, width=250, anchor="w",
                         font=ctk.CTkFont("Courier New", 12), text_color="#8899BB").pack(side="left")
            widget_builder(r)

        # ── General ──
        gen = section("GENERAL")
        self._s_threads  = ctk.StringVar(value=self.cfg.get("General", "scan_threads"))
        self._s_maxsize  = ctk.StringVar(value=self.cfg.get("General", "max_file_size_mb"))
        self._s_autoquar = ctk.BooleanVar(value=self.cfg.getbool("General", "auto_quarantine"))
        self._s_notif    = ctk.BooleanVar(value=self.cfg.getbool("General", "show_notifications"))

        row(gen, "Scan Threads", lambda p: ctk.CTkEntry(p, textvariable=self._s_threads, width=80,
            font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A", border_color="#1A3050",
            text_color="#CCDDEF").pack(side="left"))
        row(gen, "Max File Size (MB)", lambda p: ctk.CTkEntry(p, textvariable=self._s_maxsize, width=80,
            font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A", border_color="#1A3050",
            text_color="#CCDDEF").pack(side="left"))
        row(gen, "Auto Quarantine Threats", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_autoquar,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        row(gen, "Show Desktop Notifications", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_notif,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        ctk.CTkFrame(gen, fg_color="transparent", height=8).pack()

        # ── API ──
        api = section("API CONFIGURATION")
        self._s_useapi   = ctk.BooleanVar(value=self.cfg.getbool("API", "use_api"))
        self._s_provider = ctk.StringVar(value=self.cfg.get("API", "provider"))
        self._s_vtkey    = ctk.StringVar(value=self.cfg.get("API", "virustotal_key"))
        self._s_mbkey    = ctk.StringVar(value=self.cfg.get("API", "malwarebazaar_key"))
        self._s_timeout  = ctk.StringVar(value=self.cfg.get("API", "api_timeout"))

        row(api, "Enable API Lookups", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_useapi,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        row(api, "API Provider", lambda p: ctk.CTkOptionMenu(p, variable=self._s_provider,
            values=["virustotal", "malwarebazaar"], width=160,
            font=ctk.CTkFont("Courier New", 11),
            fg_color="#0A2040", button_color="#0A2040", text_color="#AABBCC").pack(side="left"))
        row(api, "VirusTotal API Key", lambda p: ctk.CTkEntry(p, textvariable=self._s_vtkey, width=380,
            show="*", font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A",
            border_color="#1A3050", text_color="#CCDDEF").pack(side="left"))
        row(api, "MalwareBazaar API Key", lambda p: ctk.CTkEntry(p, textvariable=self._s_mbkey, width=380,
            show="*", font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A",
            border_color="#1A3050", text_color="#CCDDEF").pack(side="left"))
        row(api, "API Timeout (seconds)", lambda p: ctk.CTkEntry(p, textvariable=self._s_timeout, width=80,
            font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A",
            border_color="#1A3050", text_color="#CCDDEF").pack(side="left"))
        ctk.CTkFrame(api, fg_color="transparent", height=8).pack()

        # ── Heuristics ──
        heur = section("HEURISTICS & ANALYSIS")
        self._s_heur_en  = ctk.BooleanVar(value=self.cfg.getbool("Heuristics", "enable_heuristics"))
        self._s_yara     = ctk.BooleanVar(value=self.cfg.getbool("Heuristics", "enable_yara"))
        self._s_pe       = ctk.BooleanVar(value=self.cfg.getbool("Heuristics", "enable_pe_analysis"))
        self._s_entropy  = ctk.StringVar(value=self.cfg.get("Heuristics", "entropy_threshold"))
        self._s_strings  = ctk.BooleanVar(value=self.cfg.getbool("Heuristics", "suspicious_string_check"))

        row(heur, "Enable Heuristic Analysis", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_heur_en,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        row(heur, "Enable YARA Rules", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_yara,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        row(heur, "Enable PE File Analysis", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_pe,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        row(heur, "Entropy Threshold (0-8)", lambda p: ctk.CTkEntry(p, textvariable=self._s_entropy, width=80,
            font=ctk.CTkFont("Courier New", 11), fg_color="#080D1A",
            border_color="#1A3050", text_color="#CCDDEF").pack(side="left"))
        row(heur, "Suspicious String Check", lambda p: ctk.CTkCheckBox(p, text="", variable=self._s_strings,
            fg_color="#00F5FF", border_color="#225566").pack(side="left"))
        ctk.CTkFrame(heur, fg_color="transparent", height=8).pack()

        # Save button
        ctk.CTkButton(scroll, text="💾  SAVE SETTINGS", height=44,
                      font=ctk.CTkFont("Courier New", 14, "bold"),
                      fg_color="#003355", hover_color="#004477",
                      text_color="#00F5FF", corner_radius=8,
                      command=self._save_settings).pack(fill="x", pady=10)

    def _save_settings(self):
        self.cfg.set("General", "scan_threads",       self._s_threads.get())
        self.cfg.set("General", "max_file_size_mb",   self._s_maxsize.get())
        self.cfg.set("General", "auto_quarantine",    str(self._s_autoquar.get()))
        self.cfg.set("General", "show_notifications", str(self._s_notif.get()))
        self.cfg.set("API", "use_api",             str(self._s_useapi.get()))
        self.cfg.set("API", "provider",            self._s_provider.get())
        self.cfg.set("API", "virustotal_key",      self._s_vtkey.get())
        self.cfg.set("API", "malwarebazaar_key",   self._s_mbkey.get())
        self.cfg.set("API", "api_timeout",         self._s_timeout.get())
        self.cfg.set("Heuristics", "enable_heuristics",      str(self._s_heur_en.get()))
        self.cfg.set("Heuristics", "enable_yara",            str(self._s_yara.get()))
        self.cfg.set("Heuristics", "enable_pe_analysis",     str(self._s_pe.get()))
        self.cfg.set("Heuristics", "entropy_threshold",      self._s_entropy.get())
        self.cfg.set("Heuristics", "suspicious_string_check",str(self._s_strings.get()))
        messagebox.showinfo("Settings Saved", "All settings have been saved successfully.")

    # ── LOGS PAGE ───────────────────────────────────────────────────────────
    def _build_logs_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["logs"] = page

        hdr = ctk.CTkFrame(page, fg_color="#0D1225", height=60, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="📋  APPLICATION LOGS", font=ctk.CTkFont("Courier New", 18, "bold"),
                     text_color="#00F5FF").pack(side="left", padx=20, pady=15)
        ctk.CTkButton(hdr, text="🔄 Refresh", width=90, height=34,
                      font=ctk.CTkFont("Courier New", 11),
                      fg_color="#0A2030", hover_color="#1A3040",
                      command=self._refresh_logs).pack(side="right", padx=20, pady=13)

        frame = ctk.CTkFrame(page, fg_color="#0D1225", corner_radius=12)
        frame.pack(fill="both", expand=True, padx=20, pady=15)
        self.log_text = ctk.CTkTextbox(frame, fg_color="#080D1A", text_color="#44AACC",
                                        font=ctk.CTkFont("Courier New", 11), border_width=0)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _refresh_logs(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("0.0", "end")
        log_file = LOGS_DIR / f"mal_scanner_{datetime.date.today()}.log"
        if log_file.exists():
            content = log_file.read_text()
            self.log_text.insert("end", content)
        else:
            self.log_text.insert("end", "No logs for today.")
        self.log_text.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────────
    #  SCAN LOGIC
    # ──────────────────────────────────────────────────────────────────────
    def _browse_target(self):
        stype = self.scan_type.get()
        if stype == "dir":
            path = filedialog.askdirectory()
        else:
            path = filedialog.askopenfilename()
        if path:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, path)

    def _start_scan(self):
        if self._scanning:
            messagebox.showinfo("Busy", "Scan already in progress.")
            return

        stype = self.scan_type.get()
        target = self.target_entry.get().strip()

        if stype in ("file", "dir") and not target:
            messagebox.showwarning("No Target", "Please specify a file or directory to scan.")
            return

        if stype == "quick":
            targets = self._get_quick_scan_targets()
        elif stype == "full":
            targets = self._get_full_scan_targets()
        elif stype == "dir":
            targets = list(Path(target).rglob("*"))
            targets = [str(f) for f in targets if f.is_file()]
        else:
            targets = [target]

        self._clear_results()
        self._scanning = True
        self.scan_btn.configure(state="disabled", text="⏳ Scanning…")
        use_api = self.use_api_scan.get()
        threading.Thread(target=self._run_scan, args=(targets, use_api, stype), daemon=True).start()

    def _get_quick_scan_targets(self):
        quick_dirs = []
        if sys.platform == "win32":
            quick_dirs = [
                os.environ.get("TEMP", ""),
                os.environ.get("APPDATA", ""),
                os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
            ]
        else:
            quick_dirs = ["/tmp", os.path.expanduser("~/Downloads"), "/var/tmp"]
        files = []
        for d in quick_dirs:
            if d and os.path.isdir(d):
                for f in Path(d).rglob("*"):
                    if f.is_file():
                        files.append(str(f))
        return files[:500]

    def _get_full_scan_targets(self):
        root = "C:\\" if sys.platform == "win32" else "/"
        files = []
        for f in Path(root).rglob("*"):
            if f.is_file():
                files.append(str(f))
            if len(files) >= 5000:
                break
        return files

    def _run_scan(self, targets: list, use_api: bool, scan_type: str):
        total = len(targets)
        scanned = 0
        threats_count = 0
        start_time = time.time()
        scan_results = []

        scan_id = None

        for i, target in enumerate(targets):
            if not self._scanning:
                break

            pct = (i / max(total, 1)) * 100
            self.after(0, lambda p=pct, t=target: self._update_progress(p, f"Scanning: {Path(t).name}"))

            result = self.analyzer.analyze_file(target, use_api=use_api)
            scanned += 1
            scan_results.append(result)
            self._scan_results.append(result)

            if result["threats"]:
                threats_count += len(result["threats"])

            self.after(0, lambda r=result: self._add_result_row(r))

        duration = round(time.time() - start_time, 2)

        # Save scan to DB
        scan_id = self.db.save_scan(
            targets[0] if targets else "N/A",
            scanned, threats_count, duration, scan_type
        )

        # Save threat log entries
        for result in scan_results:
            for threat in result.get("threats", []):
                self.db.save_threat(
                    scan_id,
                    result["path"],
                    threat.get("name", "Unknown"),
                    threat.get("level", "MEDIUM"),
                    threat.get("category", "MALWARE"),
                    threat.get("method", "unknown"),
                    "auto_quarantine" if (self.cfg.getbool("General", "auto_quarantine") and
                                          result["status"] == "THREAT") else "logged"
                )
                if self.cfg.getbool("General", "auto_quarantine") and result["status"] == "THREAT":
                    self.quarantine.quarantine(result["path"])

        self.logger.log("INFO", f"Scan complete: {scanned} files, {threats_count} threats, {duration}s")

        self.after(0, lambda: self._scan_complete(scanned, threats_count, duration))

    def _update_progress(self, pct: float, msg: str):
        self.progress_bar.set(pct / 100)
        self.progress_label.configure(text=msg)

    def _add_result_row(self, result: dict):
        status   = result["status"]
        filename = result["filename"]
        size     = f"{result['size'] // 1024}KB" if result["size"] else "–"
        entropy  = f"{result['entropy']:.2f}"

        if result["threats"]:
            t = result["threats"][0]
            threat_name = t.get("name", "–")
            level       = t.get("level", "–")
            method      = t.get("method", "–")
        else:
            threat_name = "–"
            level       = "–"
            method      = "–"

        tag = status
        icon = {"THREAT": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢", "ERROR": "⚫", "SKIPPED": "⚪"}.get(status, "")
        self.result_tree.insert("", "end",
            values=(f"{icon} {status}", filename, threat_name, level, method, size, entropy),
            tags=(tag,), iid=result["path"])

        # Scroll to bottom
        children = self.result_tree.get_children()
        if children:
            self.result_tree.see(children[-1])

        # Update summary
        total = len(self.result_tree.get_children())
        threats = sum(1 for c in self.result_tree.get_children()
                      if self.result_tree.item(c)["values"][0].endswith("THREAT"))
        self.result_summary.configure(text=f"{total} scanned  •  {threats} threats")

    def _scan_complete(self, scanned, threats, duration):
        self._scanning = False
        self.scan_btn.configure(state="normal", text="▶  START SCAN")
        self.progress_bar.set(1.0)
        self.progress_label.configure(text=f"✅ Done — {scanned} files in {duration}s  •  {threats} threat(s) found")
        self.result_summary.configure(text=f"{scanned} scanned  •  {threats} threats")
        self._update_stats()

    def _clear_results(self):
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        self._scan_results.clear()
        self.result_summary.configure(text="")
        self.progress_bar.set(0)
        self.progress_label.configure(text="Ready to scan")

    def _show_file_detail(self, event):
        sel = self.result_tree.selection()
        if not sel:
            return
        iid = sel[0]
        result = next((r for r in self._scan_results if r["path"] == iid), None)
        if not result:
            return

        win = ctk.CTkToplevel(self)
        win.title(f"File Detail — {result['filename']}")
        win.geometry("700x550")
        win.configure(fg_color="#0A0E1A")

        ctk.CTkLabel(win, text=f"📄 {result['filename']}",
                     font=ctk.CTkFont("Courier New", 15, "bold"),
                     text_color="#00F5FF").pack(anchor="w", padx=20, pady=(15, 5))

        txt = ctk.CTkTextbox(win, fg_color="#0D1225", text_color="#AABBCC",
                              font=ctk.CTkFont("Courier New", 11), border_width=0)
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        lines = [
            f"PATH      : {result['path']}",
            f"STATUS    : {result['status']}",
            f"SIZE      : {result['size']} bytes",
            f"ENTROPY   : {result['entropy']}",
            f"SCAN TIME : {result['scan_time']}s",
            "",
            "─── HASHES ───────────────────────────────────",
        ]
        for k, v in result.get("hashes", {}).items():
            lines.append(f"  {k.upper():<8}: {v}")

        if result.get("threats"):
            lines += ["", "─── DETECTED THREATS ─────────────────────────"]
            for t in result["threats"]:
                lines.append(f"  [{t.get('level','?')}] {t.get('name','?')} ({t.get('method','?')})")
                if t.get("description"):
                    lines.append(f"    → {t['description']}")

        if result.get("yara_matches"):
            lines += ["", "─── YARA MATCHES ─────────────────────────────"]
            for m in result["yara_matches"]:
                lines.append(f"  {m['rule']} [{m['severity']}] — {m['description']}")

        if result.get("suspicious_strings"):
            lines += ["", "─── SUSPICIOUS STRINGS ───────────────────────"]
            for s in result["suspicious_strings"]:
                lines.append(f"  ⚠  {s}")

        pe = result.get("pe_info", {})
        if pe.get("is_pe"):
            lines += ["", "─── PE ANALYSIS ──────────────────────────────"]
            for sec in pe.get("sections", []):
                lines.append(f"  Section {sec['name']:<12} entropy={sec['entropy']:.2f}  size={sec['size']}")
            if pe.get("suspicious"):
                lines.append("  Suspicious:")
                for s in pe["suspicious"]:
                    lines.append(f"    ⚠  {s}")

        txt.insert("end", "\n".join(lines))
        txt.configure(state="disabled")

    def _quarantine_selected(self):
        sel = self.result_tree.selection()
        if not sel:
            messagebox.showinfo("Select File", "Please select a file to quarantine.")
            return
        for iid in sel:
            if os.path.exists(iid):
                self.quarantine.quarantine(iid)
                self.logger.log("INFO", f"Quarantined: {iid}")
        messagebox.showinfo("Quarantined", f"{len(sel)} file(s) moved to quarantine.")

    def _delete_selected(self):
        sel = self.result_tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("Confirm Delete", f"Permanently delete {len(sel)} file(s)?"):
            return
        for iid in sel:
            try:
                if os.path.exists(iid):
                    os.remove(iid)
                    self.logger.log("INFO", f"Deleted: {iid}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete:\n{iid}\n{e}")

    def _export_report(self):
        if not self._scan_results:
            messagebox.showinfo("No Results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("JSON", "*.json"), ("All", "*.*")],
            initialfile=f"mal_scanner_report_{datetime.date.today()}"
        )
        if not path:
            return
        if path.endswith(".json"):
            with open(path, "w") as f:
                json.dump(self._scan_results, f, indent=2, default=str)
        else:
            lines = [
                f"Mal_scanner Report — {datetime.datetime.now()}",
                f"Author: {APP_AUTHOR}",
                "=" * 60,
            ]
            threats = [r for r in self._scan_results if r["threats"]]
            lines.append(f"Files scanned : {len(self._scan_results)}")
            lines.append(f"Threats found : {len(threats)}")
            lines.append("")
            for r in self._scan_results:
                if r["status"] in ("THREAT", "SUSPICIOUS"):
                    lines.append(f"[{r['status']}] {r['path']}")
                    for t in r.get("threats", []):
                        lines.append(f"  → {t.get('name')} [{t.get('level')}] via {t.get('method')}")
            with open(path, "w") as f:
                f.write("\n".join(lines))
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    def _update_stats(self):
        stats = self.db.get_stats()
        self._stat_label.configure(
            text=f"Signatures: {stats['signatures']}  •  Scans: {stats['scans']}  •  Threats: {stats['threats']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def check_dependencies():
    missing = []
    for pkg in ["customtkinter", "pefile", "requests", "yara_x"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Installing missing packages: {missing}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    check_dependencies()
    app = MalScannerApp()
    app.mainloop()
