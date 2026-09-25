# 📱 APKSentry

### Android App Security & Authentication Testing Tool

**APKSentry** is a Python-based Android application security testing tool designed to analyze **your own APKs** using both **static analysis** and **dynamic testing through ADB**.

It helps developers and security learners identify common Android security issues such as insecure manifest configurations, exported components, hardcoded secrets, weak cryptography, WebView risks, dangerous permissions, authentication-bypass risks, and sensitive data exposure.

> ⚠️ **Authorized Use Only:** Test only APKs that you own or have explicit permission to test.

---

## ✨ Features

### 🔍 Static Analysis

Analyze an APK without installing it:

* 📋 Android Manifest security analysis
* 🐞 `android:debuggable=true` detection
* 💾 `android:allowBackup=true` detection
* 🌐 Cleartext HTTP traffic detection
* 📦 Exported Activities detection
* ⚙️ Exported Services detection
* 📡 Exported Broadcast Receivers detection
* 🔑 Hardcoded API key detection
* 🔐 JWT token detection
* ☁️ AWS access key detection
* 🔥 Firebase URL detection
* 🔒 Private key detection
* 🔑 Hardcoded password detection
* 🔓 Basic-auth credentials in URLs detection
* 🧮 Weak cryptography detection
* MD5 detection
* SHA-1 detection
* DES detection
* ECB mode detection
* 🔗 WebView security checks
* JavaScript interface detection
* JavaScript enabled detection
* File access detection
* Universal file access detection
* Mixed-content detection
* 🛡️ Root-detection presence check
* 📱 Dangerous Android permission audit
* 📊 Security score generation

---

## 📲 Dynamic Analysis

APKSentry can perform authorized real-time testing using **Android Debug Bridge (ADB)**.

### Available Tests

* 📥 Install APK on connected device
* 🚀 Launch application automatically
* 🔓 Test exported Activities for authentication-bypass risks
* 📜 Monitor Android `logcat`
* 🔑 Detect possible password/token leaks in logs
* 💾 Inspect application storage
* 📂 Review SharedPreferences
* 🗄️ Review application databases
* 🔐 Check for possible plaintext secrets
* 📊 Generate JSON/CSV security reports

Dynamic testing requires a connected Android device or emulator.

---

## 🧠 How It Works

APKSentry uses two major testing layers:

```text
                    ┌─────────────────┐
                    │    APK File     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
      ┌───────────────┐             ┌───────────────┐
      │ Static Scan   │             │ Dynamic Test  │
      └───────┬───────┘             └───────┬───────┘
              │                             │
       Manifest Analysis               ADB Connection
       Secret Detection               Install / Launch
       Crypto Detection               Auth Testing
       WebView Checks                 Logcat Monitor
       Permissions                    Data Review
              │                             │
              └──────────────┬──────────────┘
                             ▼
                   ┌──────────────────┐
                   │ Security Report  │
                   │ Score + Findings │
                   └──────────────────┘
```

---

# 📦 Requirements

### Software

* Python **3.8+**
* Android Platform Tools / ADB
* `androguard`

### Optional

* Android SDK Build Tools (`aapt`) for manifest fallback analysis

### Hardware

For dynamic testing:

* Physical Android device with USB debugging enabled

**or**

* Android Emulator

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/cyberboyx404/apksentry.git
cd apksentry
```

## 2. Create Virtual Environment

### Linux / Kali

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or:

```bash
pip install androguard
```

---

# 🔧 Setup ADB

Check whether ADB is available:

```bash
adb version
```

Then check connected devices:

```bash
adb devices
```

Example:

```text
List of devices attached
XXXXXXXX    device
```

For a physical phone:

1. Enable **Developer Options**
2. Enable **USB Debugging**
3. Connect the phone through USB
4. Accept the RSA debugging prompt
5. Run:

```bash
adb devices
```

---

# 🖥️ Usage

## 🔍 Basic Static Scan

No Android device is required:

```bash
python apksentry.py -a myapp.apk
```

This analyzes the APK and displays:

* Package name
* Main Activity
* Min/Target SDK
* Debuggable status
* Backup configuration
* Permissions
* Exported components
* Hardcoded secrets
* Weak cryptography
* WebView issues
* Root detection
* Security score

---

## 📄 Export JSON Report

```bash
python apksentry.py -a myapp.apk --export json
```

A report similar to:

```text
apksentry_report_YYYYMMDD_HHMMSS.json
```

will be generated.

---

## 📊 Export CSV Report

```bash
python apksentry.py -a myapp.apk --export csv
```

---

# 📱 Dynamic Testing

Connect your authorized Android device or emulator first:

```bash
adb devices
```

Then:

```bash
python apksentry.py -a myapp.apk --dynamic
```

APKSentry will install and launch the APK through ADB.

---

# 🔓 Exported Activity Testing

Test exported Activities for potential authentication-bypass conditions:

```bash
python apksentry.py -a myapp.apk --test-exported
```

The tool attempts to launch exported Activities directly.

If a sensitive screen such as:

```text
HomeActivity
DashboardActivity
ProfileActivity
```

can be reached without the expected authentication flow, manually verify the behavior in your own application.

> The tool's "launched" result is an indicator for manual security verification, not proof by itself that an authentication vulnerability exists.

---

# 📜 Logcat Monitoring

Monitor Android logs for possible credential/token exposure:

```bash
python apksentry.py -a myapp.apk --logcat 60
```

Example:

```text
[LEAK?] password=...
[LEAK?] token=...
```

These are **keyword-based indicators** and require manual verification.

---

# 💾 Application Data Review

For an authorized debuggable application or a properly authorized rooted test device:

```bash
python apksentry.py -a myapp.apk --pull-data
```

The tool checks application storage areas such as:

```text
SharedPreferences
Databases
```

Possible plaintext secrets are flagged for review.

Output directory:

```text
apksentry_pulled_data/
```

---

# ⚡ Full Testing Pipeline

Run multiple checks together:

```bash
python apksentry.py -a myapp.apk \
    --dynamic \
    --test-exported \
    --logcat 30 \
    --pull-data \
    --export json
```

On Windows PowerShell, you can also use the command on one line:

```powershell
python apksentry.py -a myapp.apk --dynamic --test-exported --logcat 30 --pull-data --export json
```

---

# 🎯 Recommended Testing Workflow

### Step 1 — Connect Device

```bash
adb devices
```

### Step 2 — Perform Static Analysis

```bash
python apksentry.py -a myapp.apk
```

### Step 3 — Review Findings

Check:

* Exported components
* Manifest flags
* Secrets
* Weak crypto
* WebView configuration
* Permissions

### Step 4 — Install & Launch

```bash
python apksentry.py -a myapp.apk --dynamic
```

### Step 5 — Test Exported Components

```bash
python apksentry.py -a myapp.apk --test-exported
```

### Step 6 — Monitor Logs

```bash
python apksentry.py -a myapp.apk --logcat 60
```

### Step 7 — Review App Storage

```bash
python apksentry.py -a myapp.apk --pull-data
```

### Step 8 — Save Report

```bash
python apksentry.py -a myapp.apk --export json
```

---

# 📊 Security Score

APKSentry starts with:

```text
100 / 100
```

Findings reduce the score according to their severity.

| Severity    | Score Deduction |
| ----------- | --------------: |
| 🔴 Critical |             -20 |
| 🟠 High     |             -12 |
| 🟡 Medium   |              -6 |
| 🟢 Low      |              -2 |
| 🔵 Info     |               0 |

The score is a **tool-generated heuristic**, not a formal security certification or guarantee.

---

# 🔎 Detection Categories

## Manifest

Checks for:

```text
debuggable
allowBackup
usesCleartextTraffic
old minSdkVersion
```

## Exported Components

Checks:

```text
Activities
Services
Broadcast Receivers
```

## Hardcoded Secrets

Searches for indicators including:

```text
AWS Access Keys
Google API Keys
Firebase URLs
JWT Tokens
Private Keys
Slack Tokens
API Keys
Passwords
Basic Auth URLs
HTTP URLs
```

## Weak Cryptography

Detects indicators for:

```text
MD5
SHA-1
DES
ECB
Hardcoded IV/Key patterns
```

## WebView

Checks for:

```text
JavaScript interfaces
JavaScript enabled
File access
Universal file access
Mixed content
```

---

# 📁 Project Structure

```text
apksentry/
│
├── apksentry.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
└── apksentry_pulled_data/
```

Generated reports should normally be excluded from Git.

---

# 📄 requirements.txt

```txt
androguard>=3.4.0
```

---

# 🔐 Privacy & Security

APKSentry is designed for authorized application security testing.

Keep in mind:

* APKs may contain sensitive application information.
* Extracted application data may contain credentials or tokens.
* Generated reports may contain security-sensitive findings.
* Do not upload private APKs or extracted data to public repositories.
* Add generated reports and extracted data directories to `.gitignore`.

Recommended:

```gitignore
__pycache__/
*.py[cod]

venv/
.venv/

.env
.env.*

apksentry_report_*.json
apksentry_report_*.csv

apksentry_pulled_data/

*.apk
*.aab

.vscode/
.idea/

.DS_Store
Thumbs.db
```

---

# ⚠️ Responsible Use

APKSentry is intended for:

* Your own Android applications
* Applications you are authorized to assess
* Security research in controlled environments
* Educational Android security labs
* Development-time security testing
* Authorized penetration testing

Do **not** use APKSentry to access, extract, or test data from applications without authorization.

> **You are responsible for ensuring that your testing complies with applicable laws, policies, and permissions.**

---

# 🛠️ Limitations

APKSentry is a lightweight security-analysis tool and should not be considered a replacement for a complete professional mobile security assessment.

For example:

* Pattern matching can produce false positives.
* Pattern matching can miss obfuscated or dynamically generated secrets.
* Exported component detection does not automatically prove an auth bypass.
* Logcat keyword matches require manual verification.
* Security score is heuristic.
* Static string analysis is not equivalent to full source-code analysis.
* Dynamic tests depend on ADB/device configuration.
* Rooted/debuggable environments can behave differently from production builds.

Use the findings as **security indicators that require verification**.

---

# 🗺️ Roadmap

Possible future improvements:

* [ ] APK signing certificate analysis
* [ ] Certificate pinning detection
* [ ] Network security configuration analysis
* [ ] URL/domain extraction
* [ ] More Android permission intelligence
* [ ] Smali analysis
* [ ] JADX integration
* [ ] MobSF-compatible reporting
* [ ] HTML reports
* [ ] CVSS-based findings
* [ ] Improved secret detection
* [ ] Frida integration for authorized test environments
* [ ] Interactive terminal UI

---

# 🛡️ Sentry Security Suite

APKSentry is part of the **Sentry Security Suite**:

| Tool              | Purpose                                       |
| ----------------- | --------------------------------------------- |
| 🔗 **SentryURL**  | URL Safety & Analysis                         |
| 🛡️ **NetSentry** | Network Device Scanner & Firewall Detection   |
| 🔐 **PassSentry** | Password Strength & Crack-Time Auditor        |
| 📱 **APKSentry**  | Android App Security & Authentication Testing |

The goal of the Sentry Security Suite is to provide practical cybersecurity learning and defensive testing tools in a simple CLI environment.

---

# 📜 License

This project is released under the **MIT License**.

See:

```text
LICENSE
```

---

# 👨‍💻 Author

**cyberboyx404**

Frontend Web Developer • Cybersecurity Learner • Tool Builder

---

# ⭐ Support

If APKSentry helps with your authorized Android security testing or learning:

* ⭐ Star the repository
* 🐛 Report bugs
* 💡 Suggest improvements
* 🔧 Contribute improvements
* 📚 Share with other security learners

---

## ⚠️ Final Reminder

**Only test APKs that you own or have explicit authorization to assess.**

APKSentry is intended for **ethical security testing, defensive development, and cybersecurity education**.
