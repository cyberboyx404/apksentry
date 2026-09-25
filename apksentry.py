#!/usr/bin/env python3
"""
APKSentry v1.1 - Android App Security, Live Testing & Crack-Resistance Tool
Static + Dynamic (real-time via ADB) security analysis for YOUR OWN apps.

ETHICAL USE ONLY: Test only apps you own or have written permission to test.

Usage:
    python apksentry.py -a myapp.apk                      # static scan
    python apksentry.py -a myapp.apk --export json         # save report
    python apksentry.py -a myapp.apk --dynamic              # install+launch on device
    python apksentry.py -a myapp.apk --test-exported        # auth-bypass test
    python apksentry.py -a myapp.apk --logcat 30            # watch logcat 30s
    python apksentry.py -a myapp.apk --pull-data            # dump app storage

    python apksentry.py -a myapp.apk --live 60              # LIVE runtime monitoring
    python apksentry.py -a myapp.apk --crash-test 2000      # monkey stress/crash test
    python apksentry.py -a myapp.apk --check-keys           # API key exposure deep check
"""

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from androguard.core.bytecodes.apk import APK
    ANDROGUARD_OK = True
except Exception:
    try:
        from androguard.core.apk import APK
        ANDROGUARD_OK = True
    except Exception:
        ANDROGUARD_OK = False


class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    CY = "\033[96m"; BOLD = "\033[1m"; E = "\033[0m"


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.INSTALL_PACKAGES",
}

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL": r"https?://[a-z0-9\-]+\.firebaseio\.com",
    "Firebase DB URL": r"https?://[a-z0-9\-]+\.firebasedatabase\.app",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Private Key Block": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Generic API Key Assignment": r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
    "Hardcoded Password": r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"'\s]{4,}[\"']",
    "Basic Auth in URL": r"https?://[^/\s:]+:[^/\s@]+[^/\s]+",
    "Cleartext HTTP URL": r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s\"'<>]*",
}

WEAK_CRYPTO_PATTERNS = {
    "MD5 usage": r"MessageDigest\.getInstance\(\s*[\"']MD5[\"']",
    "SHA1 usage": r"MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']",
    "DES usage": r"Cipher\.getInstance\(\s*[\"']DES",
    "ECB mode": r"Cipher\.getInstance\(\s*[\"'][A-Za-z0-9]+/ECB",
    "Hardcoded IV/Key hint": r"(?i)(SecretKeySpec|IvParameterSpec)\s*\(\s*[\"'][A-Za-z0-9+/=]{8,}[\"']",
}

WEBVIEW_PATTERNS = {
    "JS Interface exposed": r"addJavascriptInterface\s*\(",
    "JS enabled": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
    "File access enabled": r"setAllowFileAccess\s*\(\s*true\s*\)",
    "Universal file access": r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
    "Mixed content allowed": r"setMixedContentMode\s*\(\s*0\s*\)",
}

ROOT_DETECTION_HINTS = [
    "RootBeer", "com.scottyab.rootbeer", "isDeviceRooted",
    "/system/app/Superuser.apk", "test-keys", "com.noshufou.android.su",
]

# NEW: Crack/tamper resistance markers (code mein ye hone chahiye)
TAMPER_CHECKS = {
    "Certificate Pinning": ["CertificatePinner", "certificatePinner", "pin-set", "ssl_pins"],
    "Anti-Debug": ["isDebuggerConnected", "Debug.isDebuggerConnected", "ptrace", "ro.debuggable"],
    "Emulator Detection": ["Build.FINGERPRINT", "goldfish", "genymotion", "isEmulator", "generic_x86"],
    "Integrity/Signature Check": ["GET_SIGNATURES", "GET_SIGNING_CERTIFICATES", "checkSignature"],
    "Play Integrity/SafetyNet": ["PlayIntegrity", "Play Integrity", "SafetyNet", "attestation"],
}

LEAK_KEYWORDS = ["password", "passwd", "token", "auth", "secret", "apikey",
                 "api_key", "credential", "bearer", "session_id", "firebase"]


# ---------------------- Static Analysis ----------------------

class StaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.findings = []
        self.score = 100
        self.package_name = None
        self.exported_components = {"activity": [], "service": [], "receiver": []}
        self.permissions = []
        self.min_sdk = None
        self.target_sdk = None
        self.debuggable = False
        self.allow_backup = True
        self.cleartext_traffic = None
        self.main_activity = None
        self.raw_strings = []
        # NEW: tamper/crack data
        self.short_class_count = 0
        self.pkg_path_in_dex = False
        self.obfuscated = False
        self.tamper = {}
        self.root_hints_found = []
        self.crack_score = None

    def add_finding(self, severity, category, message):
        self.findings.append({"severity": severity, "category": category, "message": message})
        deduction = {"critical": 20, "high": 12, "medium": 6, "low": 2, "info": 0}
        self.score -= deduction.get(severity, 0)

    def analyze_manifest_androguard(self):
        apk = APK(self.apk_path)
        self.package_name = apk.get_package()
        self.permissions = apk.get_permissions()
        self.min_sdk = apk.get_min_sdk_version()
        self.target_sdk = apk.get_target_sdk_version()
        self.debuggable = apk.get_attribute_value("application", "debuggable") == "true"
        backup_attr = apk.get_attribute_value("application", "allowBackup")
        self.allow_backup = (backup_attr != "false")
        self.main_activity = apk.get_main_activity()

        try:
            nsc = apk.get_attribute_value("application", "usesCleartextTraffic")
            self.cleartext_traffic = (nsc == "true") if nsc is not None else None
        except Exception:
            self.cleartext_traffic = None

        for comp_type, getter in [
            ("activity", apk.get_activities),
            ("service", apk.get_services),
            ("receiver", apk.get_receivers),
        ]:
            for comp in getter():
                is_exported = apk.get_attribute_value(comp_type, "exported", name=comp)
                intent_filters = apk.get_intent_filters(comp_type, comp)
                has_filter = bool(intent_filters)
                exported_flag = (is_exported == "true") or (is_exported is None and has_filter)
                if exported_flag:
                    self.exported_components[comp_type].append(comp)

        return True

    def analyze_manifest_aapt(self):
        try:
            out = subprocess.run(["aapt", "dump", "badging", self.apk_path],
                                  capture_output=True, text=True, timeout=30).stdout
        except FileNotFoundError:
            return False
        m = re.search(r"package: name='([^']+)'", out)
        if m:
            self.package_name = m.group(1)
        m = re.search(r"sdkVersion:'(\d+)'", out)
        if m:
            self.min_sdk = m.group(1)
        m = re.search(r"targetSdkVersion:'(\d+)'", out)
        if m:
            self.target_sdk = m.group(1)
        m = re.search(r"launchable-activity: name='([^']+)'", out)
        if m:
            self.main_activity = m.group(1)
        try:
            perm_out = subprocess.run(["aapt", "dump", "permissions", self.apk_path],
                                       capture_output=True, text=True, timeout=30).stdout
            self.permissions = re.findall(r"uses-permission:\s*name='([^']+)'", perm_out)
        except Exception:
            pass
        print(f"  {C.Y}[!] aapt fallback used - exported component + debuggable checks limited{C.E}")
        return True

    def extract_strings_from_dex(self):
        all_strings = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                dex_files = [n for n in z.namelist() if re.match(r"classes\d*\.dex$", n)]
                for dex in dex_files:
                    data = z.read(dex)
                    found = re.findall(rb"[\x20-\x7e]{6,}", data)
                    all_strings.extend(s.decode("ascii", errors="ignore") for s in found)
                    # NEW: obfuscation heuristic - chhote class names (R8/ProGuard ki nishani)
                    self.short_class_count += len(
                        re.findall(rb"L[a-z]{1,2}/[a-z]{1,2}(?:/[a-z]{1,2}){0,3};", data)
                    )
                    if self.package_name:
                        pkg_path = "L" + self.package_name.replace(".", "/")
                        if pkg_path.encode() in data:
                            self.pkg_path_in_dex = True
        except Exception as e:
            print(f"  {C.Y}[!] String extraction issue: {e}{C.E}")
        self.raw_strings = all_strings
        return all_strings

    def check_permissions(self):
        dangerous_found = [p for p in self.permissions if p in DANGEROUS_PERMISSIONS]
        for p in dangerous_found:
            self.add_finding("low", "Permissions", f"Dangerous permission requested: {p}")
        return dangerous_found

    def check_manifest_flags(self):
        if self.debuggable:
            self.add_finding("critical", "Manifest",
                              "android:debuggable=true - production build mein YE NAHI hona chahiye!")
        if self.allow_backup:
            self.add_finding("medium", "Manifest",
                              "android:allowBackup=true - ADB backup se app data extract ho sakta hai")
        if self.cleartext_traffic:
            self.add_finding("high", "Manifest",
                              "usesCleartextTraffic=true - unencrypted HTTP traffic allowed")
        if self.min_sdk and str(self.min_sdk).isdigit() and int(self.min_sdk) < 23:
            self.add_finding("medium", "Manifest",
                              f"minSdkVersion={self.min_sdk} - bahut purana Android bhi support (weak security defaults)")

    def check_exported_components(self):
        for comp_type, comps in self.exported_components.items():
            for comp in comps:
                sev = "high" if comp_type == "activity" else "medium"
                self.add_finding(sev, "Exported Components",
                                  f"Exported {comp_type}: {comp} - koi bhi app isse directly launch kar sakti hai")

    def scan_secrets(self):
        strings_blob = "\n".join(self.raw_strings)
        found_secrets = {}
        for name, pattern in SECRET_PATTERNS.items():
            matches = list(set(re.findall(pattern, strings_blob)))[:5]
            if matches:
                found_secrets[name] = matches
                sev = "critical" if ("Key" in name or "Password" in name or "Private" in name) else "medium"
                self.add_finding(sev, "Hardcoded Secrets",
                                  f"{name} found ({len(matches)} match(es))")
        return found_secrets

    def scan_weak_crypto(self):
        strings_blob = "\n".join(self.raw_strings)
        found = []
        for name, pattern in WEAK_CRYPTO_PATTERNS.items():
            if re.search(pattern, strings_blob):
                found.append(name)
                self.add_finding("high", "Weak Cryptography", f"{name} detected in code")
        return found

    def scan_webview_issues(self):
        strings_blob = "\n".join(self.raw_strings)
        found = []
        for name, pattern in WEBVIEW_PATTERNS.items():
            if re.search(pattern, strings_blob):
                found.append(name)
                sev = "high" if ("JS Interface" in name or "Universal" in name) else "medium"
                self.add_finding(sev, "WebView", f"{name} - potential vulnerability")
        return found

    def scan_root_detection(self):
        strings_blob = "\n".join(self.raw_strings)
        hints_found = [h for h in ROOT_DETECTION_HINTS if h in strings_blob]
        self.root_hints_found = hints_found
        if hints_found:
            self.add_finding("info", "Root Detection", f"Root detection code present ({len(hints_found)} hint(s)) - good")
        else:
            self.add_finding("low", "Root Detection", "No root detection logic found - rooted devices pe bina check chalti hai")
        return hints_found

    # NEW: Crack/tamper resistance scan
    def scan_tamper_resistance(self):
        strings_blob = "\n".join(self.raw_strings)
        self.tamper = {}
        for name, markers in TAMPER_CHECKS.items():
            found = [m for m in markers if m in strings_blob]
            self.tamper[name] = found
            if found:
                self.add_finding("info", "Tamper Resistance", f"{name}: implemented ({found[0]})")
            else:
                sev = "medium" if name in ("Certificate Pinning", "Integrity/Signature Check") else "low"
                self.add_finding(sev, "Tamper Resistance", f"{name}: NOT found - crack/hack ka risk barhta hai")

    def check_obfuscation(self):
        if self.short_class_count > 300:
            self.obfuscated = True
            self.add_finding("info", "Obfuscation",
                              f"R8/ProGuard obfuscation detected ({self.short_class_count} short classes) - good")
        elif self.short_class_count > 50:
            self.obfuscated = False
            self.add_finding("low", "Obfuscation",
                              f"Partial obfuscation only ({self.short_class_count} short classes)")
        else:
            self.obfuscated = False
            self.add_finding("medium", "Obfuscation",
                              "NO code obfuscation - APK easily decompile hoke source code padha ja sakta hai (crack risk)")

    def compute_crack_resistance(self):
        cs = 100
        if not self.obfuscated:
            cs -= 25
        if not self.tamper.get("Certificate Pinning"):
            cs -= 15
        if not self.root_hints_found:
            cs -= 15
        if not self.tamper.get("Anti-Debug"):
            cs -= 10
        if not self.tamper.get("Integrity/Signature Check"):
            cs -= 15
        if not self.tamper.get("Emulator Detection"):
            cs -= 5
        if not self.tamper.get("Play Integrity/SafetyNet"):
            cs -= 5
        if self.debuggable:
            cs -= 20
        self.crack_score = max(0, cs)
        return self.crack_score

    def crack_verdict(self):
        s = self.crack_score
        if s >= 80:
            return ("HARDENED - crack mushkil hai", C.G)
        if s >= 60:
            return ("MODERATE - kuch protections missing", C.Y)
        if s >= 40:
            return ("VULNERABLE - aasani se tamper ho sakti hai", C.Y)
        return ("EASY TO CRACK/HACK - hardening zaroori!", C.R)

    def run(self):
        print(f"{C.B}[*] Parsing manifest...{C.E}")
        parsed = False
        if ANDROGUARD_OK:
            try:
                self.analyze_manifest_androguard()
                parsed = True
            except Exception as e:
                print(f"  {C.Y}[!] androguard error: {e} - trying aapt fallback{C.E}")
        if not parsed:
            parsed = self.analyze_manifest_aapt()
        if not parsed:
            print(f"{C.R}[!] Manifest parse failed. Install androguard: pip install androguard{C.E}")

        self.check_manifest_flags()
        self.check_permissions()
        self.check_exported_components()

        print(f"{C.B}[*] Extracting strings from DEX (secrets/crypto/obfuscation scan)...{C.E}")
        self.extract_strings_from_dex()
        secrets = self.scan_secrets()
        weak_crypto = self.scan_weak_crypto()
        webview_issues = self.scan_webview_issues()
        root_hints = self.scan_root_detection()
        self.scan_tamper_resistance()
        self.check_obfuscation()
        self.compute_crack_resistance()

        self.score = max(0, self.score)
        return {
            "secrets": secrets, "weak_crypto": weak_crypto,
            "webview_issues": webview_issues, "root_hints": root_hints,
        }


def print_static_report(analyzer, extra):
    print(f"\n{C.BOLD}{'=' * 70}{C.E}")
    print(f"{C.BOLD}  APKSENTRY STATIC ANALYSIS REPORT{C.E}")
    print(f"{C.BOLD}{'=' * 70}{C.E}")
    print(f"\nPackage      : {analyzer.package_name}")
    print(f"Main Activity: {analyzer.main_activity}")
    print(f"Min/Target SDK: {analyzer.min_sdk} / {analyzer.target_sdk}")
    print(f"Debuggable   : {C.R + 'YES' + C.E if analyzer.debuggable else C.G + 'No' + C.E}")
    print(f"Allow Backup : {C.Y + 'YES' + C.E if analyzer.allow_backup else C.G + 'No' + C.E}")
    print(f"Permissions  : {len(analyzer.permissions)} total")

    print(f"\n{C.BOLD}Exported Components:{C.E}")
    for t, items in analyzer.exported_components.items():
        if items:
            print(f"  {t.capitalize()}s ({len(items)}):")
            for i in items[:10]:
                print(f"    - {i}")
            if len(items) > 10:
                print(f"    ... +{len(items) - 10} more")
    if not any(analyzer.exported_components.values()):
        print("  None found (or manifest parse limited)")

    if extra["secrets"]:
        print(f"\n{C.BOLD}{C.R}Hardcoded Secrets Found:{C.E}")
        for name, matches in extra["secrets"].items():
            print(f"  [{name}]")
            for m in matches[:3]:
                masked = m[:6] + "..." + m[-4:] if len(m) > 12 else m
                print(f"    - {masked}")

    if extra["weak_crypto"]:
        print(f"\n{C.BOLD}{C.Y}Weak Cryptography:{C.E}")
        for w in extra["weak_crypto"]:
            print(f"  - {w}")

    if extra["webview_issues"]:
        print(f"\n{C.BOLD}{C.Y}WebView Issues:{C.E}")
        for w in extra["webview_issues"]:
            print(f"  - {w}")

    # NEW: Crack Resistance Section
    if analyzer.crack_score is not None:
        verdict, vcolor = analyzer.crack_verdict()
        print(f"\n{C.BOLD}Crack/Hack Resistance: {analyzer.crack_score}/100 {vcolor}{verdict}{C.E}")
        status_map = {
            "Obfuscation": analyzer.obfuscated,
            "Certificate Pinning": bool(analyzer.tamper.get("Certificate Pinning")),
            "Root Detection": bool(analyzer.root_hints_found),
            "Anti-Debug": bool(analyzer.tamper.get("Anti-Debug")),
            "Integrity Check": bool(analyzer.tamper.get("Integrity/Signature Check")),
            "Emulator Detection": bool(analyzer.tamper.get("Emulator Detection")),
        }
        for name, ok in status_map.items():
            mark = f"{C.G}YES{C.E}" if ok else f"{C.R}NO {C.E}"
            print(f"  [{mark}] {name}")

    print(f"\n{C.BOLD}All Findings ({len(analyzer.findings)}):{C.E}")
    sev_color = {"critical": C.R, "high": C.R, "medium": C.Y, "low": C.Y, "info": C.CY}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(analyzer.findings, key=lambda x: sev_order[x["severity"]]):
        print(f"  {sev_color[f['severity']]}[{f['severity'].upper():<8}]{C.E} ({f['category']}) {f['message']}")

    # NEW: Overall hack-risk summary
    crit = sum(1 for f in analyzer.findings if f["severity"] == "critical")
    high = sum(1 for f in analyzer.findings if f["severity"] == "high")
    med = sum(1 for f in analyzer.findings if f["severity"] == "medium")
    if crit > 0 or high >= 3:
        hack_risk, hcolor = "HIGH", C.R
    elif high > 0 or med >= 4:
        hack_risk, hcolor = "MEDIUM", C.Y
    else:
        hack_risk, hcolor = "LOW", C.G
    print(f"\n{C.BOLD}Attack Surface: critical={crit} high={high} medium={med}{C.E}")
    print(f"{C.BOLD}HACK RISK VERDICT: {hcolor}{hack_risk}{C.E}")

    print(f"\n{C.BOLD}Security Score: {analyzer.score}/100{C.E}")
    if analyzer.score >= 80:
        print(f"{C.G}Verdict: GOOD{C.E}")
    elif analyzer.score >= 50:
        print(f"{C.Y}Verdict: NEEDS IMPROVEMENT{C.E}")
    else:
        print(f"{C.R}Verdict: HIGH RISK - fix before release!{C.E}")
    print()


# ---------------------- NEW: API Key Exposure Deep Check ----------------------

def check_api_exposure(analyzer, extra):
    """Apne app ki API keys/backend ka real exposure test (authorized use only)."""
    if not REQUESTS_OK:
        print(f"{C.Y}[!] requests module missing. Install: pip install requests{C.E}")
        return

    print(f"\n{C.BOLD}{'=' * 70}{C.E}")
    print(f"{C.BOLD}  API KEY EXPOSURE CHECK (LIVE){C.E}")
    print(f"{C.BOLD}{'=' * 70}{C.E}")

    fb_urls = []
    for key in ("Firebase URL", "Firebase DB URL"):
        fb_urls.extend(extra["secrets"].get(key, []))
    fb_urls = sorted(set(fb_urls))

    if fb_urls:
        print(f"\n{C.BOLD}[*] Testing {len(fb_urls)} Firebase database URL(s) for public access...{C.E}")
        for url in fb_urls:
            test_url = url.rstrip("/") + "/.json"
            try:
                r = requests.get(test_url, timeout=8)
                if r.status_code == 200:
                    analyzer.add_finding("critical", "API Exposure",
                                          f"Firebase DB PUBLICLY READABLE: {url} (bina auth data leak!)")
                    print(f"  {C.R}[CRITICAL] OPEN DATABASE! {test_url} -> 200 OK{C.E}")
                    print(f"  {C.R}           Duniya ka koi bhi banda aapka data padh/likh sakta hai!{C.E}")
                elif r.status_code in (401, 403):
                    analyzer.add_finding("info", "API Exposure",
                                          f"Firebase DB protected: {url}")
                    print(f"  {C.G}[OK] Protected {url} -> {r.status_code} (auth required){C.E}")
                else:
                    print(f"  {C.Y}[?] Unknown response {r.status_code} from {url}{C.E}")
            except Exception as e:
                print(f"  {C.Y}[!] Could not test {url}: {e}{C.E}")
    else:
        print(f"\n{C.Y}[*] Koi Firebase URL APK mein nahi mila{C.E}")

    gk = extra["secrets"].get("Google API Key", [])
    for k in gk:
        analyzer.add_finding("medium", "API Exposure",
                              "Google API key embedded - Google Cloud Console mein API restrictions lagao")
        print(f"\n{C.Y}[!] Google API Key mili: {k[:10]}...{k[-4:]}")
        print(f"    Risk: quota abuse, billing attack agar restrictions nahi hain")
        print(f"    Fix: Google Cloud Console -> Credentials -> API restrictions + quota limits")

    aws = extra["secrets"].get("AWS Access Key", [])
    for k in aws:
        analyzer.add_finding("high", "API Exposure",
                              "AWS access key embedded - turant rotate karo, backend se use karo")
        print(f"\n{C.R}[!] AWS Access Key mili: {k[:8]}...")
        print(f"    Risk: koi bhi key use karke aapka AWS account abuse kar sakta hai (billing/SSRF)")
        print(f"    Fix: Key ROTATE karo, IAM policy tight karo, key ko app mein kabhi embed na karo")

    jwt = extra["secrets"].get("JWT Token", [])
    for k in jwt:
        analyzer.add_finding("high", "API Exposure",
                              "JWT token hardcoded - expire hone ke baad bhi leak data expose karta hai")
        print(f"\n{C.R}[!] JWT Token hardcoded mila (masked)")
        print(f"    Risk: token se API access, user impersonation")

    print(f"\n{C.BOLD}API Exposure Tips:{C.E}")
    print(f"  - Koi bhi key/secret APK mein embed na karo (APK sab ke liye readable hoti hai)")
    print(f"  - Secrets ko backend proxy ke peeche rakho; app sirf apne server se baat kare")
    print(f"  - Firebase: database rules set karo (auth != null), test mode production mein mat chhodo")
    print()


# ---------------------- Dynamic Analysis (ADB) ----------------------

class DynamicTester:
    def __init__(self, apk_path, analyzer: StaticAnalyzer):
        self.apk_path = apk_path
        self.analyzer = analyzer

    def check_adb(self):
        try:
            subprocess.run(["adb", "version"], capture_output=True, timeout=5)
            return True
        except FileNotFoundError:
            print(f"{C.R}[!] adb not found. Install Android Platform Tools & add to PATH.{C.E}")
            return False

    def get_devices(self):
        out = subprocess.run(["adb", "devices"], capture_output=True, text=True,
                              timeout=10, encoding="utf-8", errors="replace").stdout
        lines = [l for l in out.strip().splitlines()[1:] if l.strip()]
        return [l.split()[0] for l in lines if "device" in l]

    def install(self):
        print(f"{C.B}[*] Installing {self.apk_path} ...{C.E}")
        r = subprocess.run(["adb", "install", "-r", self.apk_path], capture_output=True,
                            text=True, timeout=120, encoding="utf-8", errors="replace")
        if "Success" in r.stdout:
            print(f"{C.G}[+] Installed successfully{C.E}")
            return True
        print(f"{C.R}[!] Install failed: {r.stdout}\n{r.stderr}{C.E}")
        return False

    def launch_main(self):
        pkg = self.analyzer.package_name
        act = self.analyzer.main_activity
        if not pkg or not act:
            print(f"{C.Y}[!] Package/main activity unknown, cannot launch{C.E}")
            return
        component = f"{pkg}/{act}" if not act.startswith(".") else f"{pkg}/{pkg}{act}"
        print(f"{C.B}[*] Launching {component} ...{C.E}")
        subprocess.run(["adb", "shell", "am", "start", "-n", component],
                        capture_output=True, text=True, timeout=15,
                        encoding="utf-8", errors="replace")

    def test_exported_activities(self):
        pkg = self.analyzer.package_name
        activities = self.analyzer.exported_components.get("activity", [])
        if not activities:
            print(f"{C.Y}[!] No exported activities found in static scan{C.E}")
            return []

        print(f"\n{C.BOLD}[*] Testing {len(activities)} exported activities (auth bypass check){C.E}")
        results = []
        for act in activities:
            component = f"{pkg}/{act}"
            r = subprocess.run(["adb", "shell", "am", "start", "-n", component],
                                capture_output=True, text=True, timeout=15,
                                encoding="utf-8", errors="replace")
            success = "Error" not in r.stdout and "Error" not in r.stderr
            status = f"{C.R}LAUNCHED (potential bypass!){C.E}" if success else f"{C.G}blocked/failed{C.E}"
            print(f"  {component} -> {status}")
            results.append({"activity": component, "launched": success})
            time.sleep(1)
        print(f"\n{C.Y}[!] Manually verify: agar koi 'sensitive' activity (Home/Dashboard/Profile){C.E}")
        print(f"{C.Y}    bina login ke launch hui, to ye AUTH BYPASS vulnerability hai!{C.E}")
        return results

    def watch_logcat(self, duration=30):
        print(f"\n{C.BOLD}[*] Watching logcat for {duration}s - looking for leaked secrets...{C.E}")
        subprocess.run(["adb", "logcat", "-c"], capture_output=True)
        proc = subprocess.Popen(
            ["adb", "logcat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace"
        )
        found = []
        start = time.time()
        try:
            while time.time() - start < duration:
                line = proc.stdout.readline()
                if not line:
                    continue
                low = line.lower()
                if any(k in low for k in LEAK_KEYWORDS):
                    found.append(line.strip())
                    print(f"  {C.R}[LEAK?]{C.E} {line.strip()[:120]}")
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()

        if not found:
            print(f"{C.G}[+] No obvious keyword leaks detected in logcat during window{C.E}")
        else:
            print(f"\n{C.R}[!] {len(found)} suspicious log line(s) captured{C.E}")
        return found

    def pull_app_data(self):
        pkg = self.analyzer.package_name
        print(f"\n{C.B}[*] Attempting to pull app data for {pkg} (needs debuggable app or rooted device)...{C.E}")
        r = subprocess.run(["adb", "shell", "run-as", pkg, "ls", "-R",
                             f"/data/data/{pkg}/shared_prefs", f"/data/data/{pkg}/databases"],
                            capture_output=True, text=True, timeout=15,
                            encoding="utf-8", errors="replace")
        if r.returncode != 0 or "not debuggable" in r.stderr.lower():
            print(f"{C.Y}[!] Could not access app data - app not debuggable & device not rooted{C.E}")
            print(f"    stderr: {r.stderr.strip()}")
            return None
        print(f"{C.G}[+] App data structure:{C.E}")
        print(r.stdout)

        os.makedirs("apksentry_pulled_data", exist_ok=True)
        for folder in ["shared_prefs", "databases"]:
            local_dir = os.path.join("apksentry_pulled_data", folder)
            os.makedirs(local_dir, exist_ok=True)
            list_r = subprocess.run(["adb", "shell", "run-as", pkg, "ls", f"/data/data/{pkg}/{folder}"],
                                     capture_output=True, text=True, timeout=15,
                                     encoding="utf-8", errors="replace")
            files = [f.strip() for f in list_r.stdout.splitlines() if f.strip()]
            for fname in files:
                remote = f"/data/data/{pkg}/{folder}/{fname}"
                cat_r = subprocess.run(["adb", "shell", "run-as", pkg, "cat", remote],
                                        capture_output=True, text=True, timeout=15,
                                        encoding="utf-8", errors="replace")
                with open(os.path.join(local_dir, fname), "w", encoding="utf-8", errors="ignore") as f:
                    f.write(cat_r.stdout)
                print(f"    Pulled: {folder}/{fname}")

                for name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, cat_r.stdout):
                        print(f"    {C.R}[!] Possible {name} found in {fname} (PLAINTEXT STORAGE!){C.E}")
        print(f"\n{C.G}[+] Data saved to ./apksentry_pulled_data/{C.E}")

    # ---------------- NEW: Live Runtime Monitoring ----------------

    def get_pid(self, pkg):
        try:
            r = subprocess.run(["adb", "shell", "pidof", pkg], capture_output=True,
                                text=True, timeout=10, encoding="utf-8", errors="replace")
            parts = r.stdout.strip().split()
            if parts and parts[0].isdigit():
                return int(parts[0])
        except Exception:
            pass
        try:
            r = subprocess.run(["adb", "shell", "ps", "-A"], capture_output=True,
                                text=True, timeout=10, encoding="utf-8", errors="replace")
            for line in r.stdout.splitlines():
                if pkg in line:
                    for p in line.split()[1:3]:
                        if p.isdigit():
                            return int(p)
        except Exception:
            pass
        return None

    def get_usage(self, pkg):
        for cmd in (["adb", "shell", "top", "-n", "1", "-b"], ["adb", "shell", "top", "-n", "1"]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                    encoding="utf-8", errors="replace")
                for line in r.stdout.splitlines():
                    if pkg in line:
                        return line.strip()[:110]
            except Exception:
                continue
        return None

    def live_monitor(self, duration=60):
        pkg = self.analyzer.package_name
        print(f"\n{C.BOLD}{'=' * 70}{C.E}")
        print(f"{C.BOLD}  LIVE RUNTIME MONITOR - {pkg} ({duration}s){C.E}")
        print(f"{C.BOLD}{'=' * 70}{C.E}")
        print(f"{C.Y}[i] App ko ab normally use karo (login, clicks, sab kuch).{C.E}")
        print(f"{C.Y}[i] Tool crash / ANR / restart / secret-leaks real-time pakdega.{C.E}\n")

        pid = self.get_pid(pkg)
        if pid is None:
            print(f"{C.Y}[*] App chal nahi rahi - launch kar raha hoon...{C.E}")
            self.launch_main()
            time.sleep(3)
            pid = self.get_pid(pkg)

        initial_pid = pid
        print(f"{C.B}[*] PID: {pid} | Monitoring started...{C.E}\n")

        subprocess.run(["adb", "logcat", "-c"], capture_output=True)
        proc = subprocess.Popen(
            ["adb", "logcat", "-v", "brief"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, encoding="utf-8", errors="replace"
        )
        q = queue.Queue()

        def reader():
            try:
                for line in proc.stdout:
                    q.put(line.rstrip("\n"))
            except Exception:
                pass
            q.put(None)

        threading.Thread(target=reader, daemon=True).start()

        crashes, anrs, leaks = [], [], []
        restarts = 0
        last_pid = pid
        last_check = 0.0
        start = time.time()

        try:
            while time.time() - start < duration:
                # logcat drain
                while True:
                    try:
                        line = q.get_nowait()
                    except queue.Empty:
                        break
                    if line is None:
                        break
                    low = line.lower()
                    if "fatal exception" in low or "beginning of crash" in low:
                        crashes.append(line)
                        print(f"  {C.R}[CRASH!] {line[:130]}{C.E}")
                    elif "signal 11" in low or "tombstone" in low:
                        crashes.append(line)
                        print(f"  {C.R}[SIGSEGV!] {line[:130]}{C.E}")
                    elif "anr in" in low or "input dispatching timed out" in low:
                        anrs.append(line)
                        print(f"  {C.Y}[ANR!] {line[:130]}{C.E}")
                    elif pkg in low and any(k in low for k in LEAK_KEYWORDS):
                        leaks.append(line)
                        print(f"  {C.R}[LEAK?] {line[:130]}{C.E}")

                # har 5 sec: pid + usage check
                now = time.time()
                if now - last_check >= 5:
                    last_check = now
                    cur_pid = self.get_pid(pkg)
                    if cur_pid is None:
                        print(f"  {C.R}[!] App process GAYAB (crash/kill hua?){C.E}")
                    elif last_pid is not None and cur_pid != last_pid:
                        restarts += 1
                        print(f"  {C.R}[!] PID CHANGE {last_pid} -> {cur_pid} (app restart hui = crash/pause kill){C.E}")
                    last_pid = cur_pid
                    usage = self.get_usage(pkg)
                    if usage:
                        print(f"  {C.CY}[LIVE] {usage}{C.E}")
                time.sleep(0.2)
        except KeyboardInterrupt:
            print(f"\n{C.Y}[*] Monitor user ne roka{C.E}")
        finally:
            proc.terminate()

        # Summary
        print(f"\n{C.BOLD}{'=' * 70}{C.E}")
        print(f"{C.BOLD}  LIVE MONITOR SUMMARY{C.E}")
        print(f"{C.BOLD}{'=' * 70}{C.E}")
        print(f"  Crashes detected : {C.R if crashes else C.G}{len(crashes)}{C.E}")
        print(f"  ANRs detected    : {C.Y if anrs else C.G}{len(anrs)}{C.E}")
        print(f"  Restarts         : {C.R if restarts else C.G}{restarts}{C.E}")
        print(f"  Secret leaks     : {C.R if leaks else C.G}{len(leaks)}{C.E}")
        stable = not crashes and not anrs and restarts == 0
        print(f"\n  Stability Verdict: {C.G if stable else C.R}{'STABLE' if stable else 'ISSUES FOUND - upar details dekho'}{C.E}")
        print()
        return {"crashes": crashes, "anrs": anrs, "restarts": restarts, "leaks": leaks}

    # ---------------- NEW: Crash/Stress Test (Monkey) ----------------

    def crash_test(self, events=1000, throttle=30):
        pkg = self.analyzer.package_name
        print(f"\n{C.BOLD}{'=' * 70}{C.E}")
        print(f"{C.BOLD}  CRASH/STRESS TEST (Monkey) - {events} events{C.E}")
        print(f"{C.BOLD}{'=' * 70}{C.E}")

        if self.get_pid(pkg) is None:
            print(f"{C.Y}[*] App chal nahi rahi - launch kar raha hoon...{C.E}")
            self.launch_main()
            time.sleep(3)

        subprocess.run(["adb", "logcat", "-c"], capture_output=True)

        # Generous timeout: throttle*events + processing overhead + big safety buffer
        base_time = (events * throttle) / 1000  # seconds
        timeout = int(base_time * 3) + 180  # 3x buffer + 3 min safety margin
        print(f"{C.B}[*] Monkey chala raha hoon... (max {timeout}s wait, usually faster){C.E}")

        proc = subprocess.Popen(
            ["adb", "shell", "monkey", "-p", pkg, "--throttle", str(throttle),
             "--ignore-security-exceptions", "-v", str(events)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )

        out = ""
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            try:
                out, _ = proc.communicate(timeout=10)
            except Exception:
                out = ""
            print(f"\n  {C.R}[!] Monkey {timeout}s ke baad bhi complete nahi hua!{C.E}")
            print(f"  {C.R}    Ye khud ek CRASH/HANG indicator hai (app freeze ho gayi ya ANR){C.E}")

        out = out or ""
        injected = re.search(r"Events injected:\s*(\d+)", out)
        injected_n = int(injected.group(1)) if injected else 0
        monkey_crash = ("// CRASH" in out) or ("Application died" in out) or ("aborted" in out.lower())

        still_alive = self.get_pid(pkg) is not None

        # logcat se fatal exceptions nikalo
        try:
            lr = subprocess.run(["adb", "logcat", "-d"], capture_output=True, text=True,
                                 timeout=15, encoding="utf-8", errors="replace")
            fatals = [l for l in (lr.stdout or "").splitlines() if "FATAL EXCEPTION" in l]
        except Exception:
            fatals = []

        print(f"\n{C.BOLD}Results:{C.E}")
        print(f"  Events injected : {injected_n}/{events}")
        print(f"  Monkey timeout  : {C.R + 'YES (hang/freeze)' + C.E if timed_out else C.G + 'No' + C.E}")
        print(f"  Monkey crash    : {C.R + 'YES' + C.E if monkey_crash else C.G + 'No' + C.E}")
        print(f"  App still alive : {C.G + 'YES' + C.E if still_alive else C.R + 'NO (app died!)' + C.E}")
        print(f"  FATAL exceptions: {C.R if fatals else C.G}{len(fatals)}{C.E}")
        for f in fatals[:5]:
            print(f"    {C.R}{f[:120]}{C.E}")

        if timed_out or monkey_crash or fatals or not still_alive:
            print(f"\n  {C.R}CRASH RISK: HIGH - app crash/hang ho rahi hai. Fix karo!{C.E}")
            if timed_out:
                print(f"  {C.Y}Tip: App freeze/ANR ho sakta hai - main thread block check karo{C.E}")
                print(f"  {C.Y}     (network calls / heavy work UI thread pe to nahi ho raha?){C.E}")
            if fatals:
                print(f"  {C.Y}Tip: 'adb logcat | grep FATAL' se pura stack trace dekho{C.E}")
        elif injected_n < events:
            print(f"\n  {C.Y}CRASH RISK: MEDIUM - monkey ne pura run complete nahi kiya.{C.E}")
        else:
            print(f"\n  {C.G}CRASH RISK: LOW - {events} random events handle kar liye. Solid!{C.E}")
        print()
# ---------------------- Export ----------------------

def export_report(analyzer, extra, fmt):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "package": analyzer.package_name,
        "main_activity": analyzer.main_activity,
        "min_sdk": analyzer.min_sdk,
        "target_sdk": analyzer.target_sdk,
        "debuggable": analyzer.debuggable,
        "allow_backup": analyzer.allow_backup,
        "cleartext_traffic": analyzer.cleartext_traffic,
        "permissions": analyzer.permissions,
        "exported_components": analyzer.exported_components,
        "secrets_found": {k: len(v) for k, v in extra["secrets"].items()},
        "weak_crypto": extra["weak_crypto"],
        "webview_issues": extra["webview_issues"],
        "obfuscated": analyzer.obfuscated,
        "tamper_resistance": {k: bool(v) for k, v in analyzer.tamper.items()},
        "crack_resistance_score": analyzer.crack_score,
        "score": analyzer.score,
        "findings": analyzer.findings,
        "scan_time": ts,
    }
    fname = f"apksentry_report_{ts}.{fmt}"
    if fmt == "json":
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        import csv
        with open(fname, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["severity", "category", "message"])
            for finding in analyzer.findings:
                w.writerow([finding["severity"], finding["category"], finding["message"]])
    print(f"{C.G}[+] Report saved: {fname}{C.E}")


# ---------------------- Main ----------------------

BANNER = f"""{C.BOLD}{C.CY}

     █████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
    ███████║██████╔╝█████╔╝ ███████╗██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
    ██╔══██║██╔═══╝ ██╔═██╗ ╚════██║██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
    ██║  ██║██║     ██║  ██╗███████║██║ ╚████║   ██║   ██║  ██║   ██║
    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝

               [ A P K S E N T R Y ]  v1.1
     Android App Security, Live Testing & Crack-Resistance Tool

    ─────────────────────────────────────────────────────────────────
     Static • Live Monitor • Crash Test • API Exposure • ADB • Auth
    ─────────────────────────────────────────────────────────────────

       {C.Y}[!] Authorized use only — test your own APKs.{C.E}

{C.E}"""


def main():
    parser = argparse.ArgumentParser(description="APKSentry - Android App Security Testing Tool")
    parser.add_argument("-a", "--apk", required=True, help="Path to APK file")
    parser.add_argument("--export", choices=["json", "csv"], help="Export report")
    parser.add_argument("--dynamic", action="store_true", help="Install & launch app on connected device")
    parser.add_argument("--test-exported", action="store_true", help="Test exported activities for auth bypass")
    parser.add_argument("--logcat", type=int, metavar="SECONDS", help="Watch logcat for N seconds")
    parser.add_argument("--pull-data", action="store_true", help="Extract app's shared_prefs/databases")
    parser.add_argument("--live", type=int, nargs="?", const=60, metavar="SECONDS",
                         help="LIVE runtime monitor (crash/ANR/leak/restart) - app use karte waqt")
    parser.add_argument("--crash-test", type=int, nargs="?", const=1000, metavar="EVENTS",
                         help="Monkey stress test (default 1000 events) - crash risk")
    parser.add_argument("--check-keys", action="store_true",
                         help="API key exposure deep check (Firebase open DB live test etc.)")
    args = parser.parse_args()

    print(BANNER)

    if not os.path.exists(args.apk):
        print(f"{C.R}[!] APK file not found: {args.apk}{C.E}")
        sys.exit(1)

    if not ANDROGUARD_OK:
        print(f"{C.Y}[!] androguard not installed - limited aapt fallback use hoga{C.E}")
        print(f"    Install for best results: pip install androguard\n")

    analyzer = StaticAnalyzer(args.apk)
    extra = analyzer.run()
    print_static_report(analyzer, extra)

    # NEW: API exposure check (device ki zaroorat nahi)
    if args.check_keys:
        check_api_exposure(analyzer, extra)

    if args.export:
        export_report(analyzer, extra, args.export)

    device_flags = any([args.dynamic, args.test_exported, args.logcat,
                         args.pull_data, args.live, args.crash_test])
    if device_flags:
        tester = DynamicTester(args.apk, analyzer)
        if not tester.check_adb():
            sys.exit(1)
        devices = tester.get_devices()
        if not devices:
            print(f"{C.R}[!] No device/emulator connected. Connect one and enable USB debugging.{C.E}")
            sys.exit(1)
        print(f"{C.G}[+] Device connected: {devices[0]}{C.E}")

        if args.dynamic:
            if tester.install():
                tester.launch_main()

        if args.test_exported:
            tester.test_exported_activities()

        if args.live:
            tester.live_monitor(args.live)

        if args.crash_test:
            tester.crash_test(args.crash_test)

        if args.logcat:
            tester.watch_logcat(args.logcat)

        if args.pull_data:
            tester.pull_app_data()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}Cancelled by user.{C.E}")
        sys.exit(0)