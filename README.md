# 🔬 Mal_scanner v2.0.0
> **Signature-Based Malware Detection Tool**  
> *Author: [Yx0R](https://github.com/Yx0R)*,  [Yash Gaikwad](https://yash-gaikwad.onrender.com) *

---

## Overview

Mal_scanner is a professional-grade, signature-based malware detection tool with a modern dark GUI. It combines multiple detection engines into a unified interface — from hash-based signature matching to YARA rules, PE analysis, entropy checks, and live API lookups.

---

## Features

### Detection Engines
| Engine | Description |
|---|---|
| **Signature DB (local)** | MD5 / SHA1 / SHA256 hash matching against SQLite database |
| **YARA Rules** | Static analysis via customizable YARA rule files |
| **PE Analysis** | PE header inspection, import table heuristics, section entropy |
| **Entropy Analysis** | Detects packed/encrypted files via Shannon entropy |
| **String Heuristics** | Scans for suspicious byte patterns (shellcode, PowerShell, registry keys, etc.) |
| **API Lookups** | VirusTotal & MalwareBazaar hash reputation (configurable in Settings) |

### Scan Modes
- **File Scan** — single file
- **Directory Scan** — recursive directory traversal
- **Quick Scan** — Temp, Downloads, AppData (common drop zones)
- **Full System Scan** — full drive traversal

### Management
- **Quarantine Vault** — neutralize threats (base64-encodes and isolates files), restore or delete permanently
- **Signature Manager** — add custom signatures, import CSV bulk, fetch from API
- **Scan History** — all previous scans logged to SQLite
- **Dashboard** — live stats + recent threat feed
- **Report Export** — TXT or JSON scan reports

---

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
python mal_scanner.py
```

### Dependencies
- `customtkinter` — modern Tkinter UI
- `pefile` — Windows PE file analysis
- `requests` — API calls (VirusTotal / MalwareBazaar)
- `yara-x` — YARA rule engine (Python bindings)

> **Note:** On first run, missing packages are auto-installed.

---

## API Configuration

Go to **⚙️ Settings → API Configuration**:

### VirusTotal
1. Sign up at [virustotal.com](https://virustotal.com)
2. Go to API key section in your profile
3. Paste the key in the VirusTotal API Key field
4. Set Provider to `virustotal`, enable API Lookups

### MalwareBazaar
1. Register at [bazaar.abuse.ch](https://bazaar.abuse.ch)
2. Obtain your API key
3. Paste in the MalwareBazaar API Key field
4. Set Provider to `malwarebazaar`

---

## Signature Database

The local SQLite database at `mal_scanner_data/signatures.db` includes:
- 10+ built-in signatures (EICAR, WannaCry, Mirai, Emotet, CobaltStrike, Ryuk, etc.)
- User-added custom signatures
- CSV bulk import support
- API-fetched signatures

### CSV Import Format
```csv
name,hash_type,hash_value,threat_level,category,description
MyMalware,sha256,abcdef...,HIGH,TROJAN,Custom detection
```

---

## YARA Rules

Default rules are auto-generated at `mal_scanner_data/yara_rules/default.yar`.  
Add or edit rules there; they reload on each scan.

Built-in rules detect:
- Encoded PowerShell commands
- Ransomware patterns (ransom notes, encryption keywords)
- Suspicious PE imports (process injection, hollowing)
- PHP webshells
- Keylogger indicators

---

## Data Locations

```
mal_scanner_data/
├── signatures.db       # SQLite signature + scan history database
├── config.ini          # All settings
├── quarantine/         # Quarantined files (base64-neutralized)
├── logs/               # Daily log files
└── yara_rules/
    └── default.yar     # YARA rule set
```

---

## Settings Reference

| Setting | Default | Description |
|---|---|---|
| Scan Threads | 4 | Concurrent file analysis workers |
| Max File Size | 100 MB | Files larger than this are skipped |
| Auto Quarantine | Off | Automatically quarantine detected threats |
| Entropy Threshold | 7.2 | Entropy score that triggers suspicion (0–8) |
| API Timeout | 10s | Request timeout for API lookups |

---

## License

MIT License — Free for personal and educational use.

---

*Built with ❤️ by Yx0R / Yash Gaikwad*
