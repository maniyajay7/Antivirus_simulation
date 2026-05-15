# CwX — Basic Antivirus Simulation (Signature & Heuristic Scanner)

> **Author:** Maniya Jay 
> **Academic Year:** 2025–2026  
> **Domain:** Cybersecurity Architecture & Penetration Testing Fundamentals

---

## 📋 Project Overview

CwX is a **terminal-based antivirus simulation** built in Python that demonstrates how real-world endpoint protection platforms detect and neutralize threats. It combines two industry-standard detection techniques:

1. **Signature-Based Scanning** — Comparing file hashes against a known malware database
2. **Heuristic Entropy Analysis** — Detecting packed/encrypted payloads using Shannon entropy

The tool also features **real-time filesystem monitoring** (using OS-level events), **automated quarantine isolation**, and **SIEM-compatible JSON audit logging** — core components of modern EDR/XDR security stacks.

---

## 🧠 Concepts Used

### 1. Cryptographic Hashing (SHA-256)
Every file can be reduced to a unique 256-bit "fingerprint" using the SHA-256 algorithm. This hash changes completely if even a single byte in the file is modified (the **avalanche effect**). Antivirus engines maintain databases of known malware hashes and compare scanned files against them for instant identification.

**Why SHA-256 in 2026?**  
SHA-256 remains unbroken and is a NIST-approved standard. It is used by Bitcoin, TLS certificates, and every major antivirus vendor for signature generation.

### 2. Signature-Based Detection
The most fundamental antivirus technique. A database (`signatures.json`) maps known malware SHA-256 hashes to threat names and severity levels. During a scan, each file's hash is computed and checked against this database.

- **Strength:** Instant, accurate detection of known threats with zero false positives.
- **Weakness:** Cannot detect brand-new (zero-day) malware that isn't in the database yet.

### 3. Shannon Entropy Heuristic Analysis
When a file does NOT match any known signature, the scanner applies a second detection layer: **entropy analysis**.

Shannon entropy measures the randomness/information density of data on a scale of 0.0 to 8.0 bits per byte:

| Entropy Range | Typical Content | Threat Assessment |
|---|---|---|
| 0.0 – 4.0 | Plain text, source code | Benign |
| 4.0 – 6.0 | Structured data, HTML | Likely benign |
| 6.0 – 7.5 | Compressed files (ZIP, JPEG) | Normal compression |
| **7.5 – 8.0** | **Encrypted/packed payloads** | **⚠ Suspicious** |

Malware authors routinely **pack** (compress/encrypt) their payloads using tools like UPX, Themida, or custom XOR encryption to evade signature scanners. This packing pushes the file's entropy close to the theoretical maximum of 8.0, which this heuristic engine detects.

### 4. Automated Quarantine
When a threat is confirmed (either by signature match or high entropy), the file is immediately **moved** to an isolated `/quarantine` directory using `shutil.move()`. This prevents the malicious file from being executed while preserving it for forensic analysis.

### 5. Real-Time Filesystem Monitoring (Watchdog)
The `watchdog` library hooks into the OS's native filesystem notification API (`ReadDirectoryChangesW` on Windows, `inotify` on Linux) to detect new or modified files the instant they appear on disk — before the user ever opens them. This mirrors how production EDR agents work.

### 6. SIEM-Compatible Audit Logging
Every action is logged in **JSON Lines (JSONL)** format with ISO-8601 timestamps, event types, severity levels, and metadata payloads. This format is directly ingestible by enterprise SIEM platforms (Splunk, Elastic Security, Microsoft Sentinel, Google Chronicle).

---

## 🏗 Project Structure

```
basic_antivirus_sim/
├── main.py                    # Entry point — UI, menus, boot sequence
├── scanner/
│   ├── __init__.py
│   ├── engine.py              # SHA-256 hashing & signature matching
│   └── heuristics.py          # Shannon entropy analyzer
├── monitor/
│   ├── __init__.py
│   └── watcher.py             # Real-time filesystem monitoring
├── utils/
│   ├── __init__.py
│   └── logger.py              # JSONL audit logger
├── database/
│   └── signatures.json        # Malware signature database
├── scan_target/               # ← Place files here to scan
├── quarantine/                # ← Threats are isolated here
├── logs/
│   └── cwx_audit.jsonl        # Auto-generated audit trail
├── requirements.txt
└── README.md
```

---

## ⚡ Technology Stack

| Technology | Purpose | Version |
|---|---|---|
| **Python 3.11+** | Core language — industry standard for security tools | 3.11+ |
| **hashlib** | SHA-256 cryptographic hashing (stdlib) | Built-in |
| **math** | Shannon entropy computation (stdlib) | Built-in |
| **rich** | Premium terminal UI — tables, progress bars, panels | 13.0+ |
| **watchdog** | Real-time filesystem event monitoring | 4.0+ |
| **shutil** | Safe file quarantine operations (stdlib) | Built-in |
| **json** | SIEM-compatible log serialization (stdlib) | Built-in |

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)

### Step-by-Step

```bash
# 1. Navigate to the project directory
cd basic_antivirus_sim

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py
```

---

## 🧪 Testing: How to Trigger a Quarantine

### Test 1: Signature Match (Trojan Simulation)
Create a test file whose hash matches a signature in the database:

```bash
echo test> scan_target\malware_test.txt
```

> **Note:** The string `test` (with a newline) produces the hash `f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2`, which matches `Trojan.TestPayload.CwX` in the signature database.

### Test 2: High Entropy File (Heuristic Detection)
Create a file filled with random bytes to simulate a packed/encrypted payload:

```bash
python -c "import os; open('scan_target/encrypted_payload.bin','wb').write(os.urandom(4096))"
```

This file will have entropy close to 8.0 and will be flagged as suspicious by the heuristic engine.

### Test 3: Clean File
```bash
echo This is a normal safe document> scan_target\safe_doc.txt
```

This file will pass both checks and be marked as **CLEAN**.

---

## 🔮 2026 & Future Perspective

This project implements the **foundational detection layers** that every modern security platform builds upon:

| Layer | This Project | Production (2026 EDR/XDR) |
|---|---|---|
| Signature Matching | ✅ SHA-256 database | ✅ + cloud-streamed real-time updates |
| Heuristic Analysis | ✅ Shannon entropy | ✅ + structural PE/ELF header analysis |
| Behavioral Analysis | — | ✅ Sandbox detonation, API hooking |
| Machine Learning | — | ✅ Neural network classifiers |
| Memory Scanning | — | ✅ AMSI, ETW tracing |
| Threat Intelligence | — | ✅ Global cloud reputation scoring |

Modern platforms like **CrowdStrike Falcon**, **SentinelOne Singularity**, and **Microsoft Defender ATP** all start with exactly these fundamental techniques before applying their advanced AI and behavioral layers.

---

## ⚖️ Ethical Disclaimer

This tool is developed **exclusively for educational purposes** as part of an academic cybersecurity curriculum at DEPSTAR. It does not detect real-world malware unless real malware signatures are added to the database. All scanning, quarantine, and monitoring functions are sandboxed to local directories.

> **Always practice security research ethically, legally, and only on systems you own or have explicit authorization to test.**

---

## 📄 License

Academic project
