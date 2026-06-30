"""
DroidScan — Module 1: Static Analysis
======================================
Decompiles APK and extracts:
  - Manifest permissions
  - Suspicious API calls
  - Hardcoded IPs, URLs, and strings
  - Certificate info
  - YARA rule matches

Dependencies:
    pip install androguard yara-python
    Install JADX: https://github.com/skylot/jadx/releases
"""

import re
import json
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Optional
import yara
from androguard.misc import AnalyzeAPK


# ─── Dangerous permissions to flag ───────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":               "Read SMS messages",
    "android.permission.SEND_SMS":               "Send SMS messages",
    "android.permission.RECEIVE_SMS":            "Intercept incoming SMS",
    "android.permission.READ_CONTACTS":          "Read device contacts",
    "android.permission.ACCESS_FINE_LOCATION":   "Precise GPS location",
    "android.permission.RECORD_AUDIO":           "Microphone access",
    "android.permission.CAMERA":                 "Camera access",
    "android.permission.READ_CALL_LOG":          "Read call logs",
    "android.permission.PROCESS_OUTGOING_CALLS": "Intercept outgoing calls",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Auto-start on boot",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write to storage",
    "android.permission.REQUEST_INSTALL_PACKAGES":"Install other APKs",
    "android.permission.BIND_DEVICE_ADMIN":      "Device admin rights",
    "android.permission.SYSTEM_ALERT_WINDOW":    "Draw over other apps",
}

# ─── Suspicious API calls ─────────────────────────────────────────────────────

SUSPICIOUS_APIS = {
    "getDeviceId":            "Harvests IMEI/device ID",
    "getSubscriberId":        "Harvests SIM serial (IMSI)",
    "getLine1Number":         "Harvests phone number",
    "sendTextMessage":        "Sends SMS silently",
    "execShell":              "Executes shell commands",
    "Runtime.exec":           "Spawns subprocess",
    "DexClassLoader":         "Loads external DEX at runtime",
    "loadLibrary":            "Loads native library",
    "getInstalledPackages":   "Enumerates installed apps",
    "setWifiEnabled":         "Toggles WiFi",
    "getCellLocation":        "Tracks cell tower location",
    "HttpURLConnection":      "Makes HTTP requests",
    "javax.crypto":           "Uses encryption",
    "Base64.decode":          "Decodes Base64 data",
    "Cipher.getInstance":     "Symmetric encryption",
    "KeyGenerator":           "Generates crypto keys",
    "TelephonyManager":       "Accesses telephony",
}

# ─── IOC regex patterns ───────────────────────────────────────────────────────

PATTERNS = {
    "ipv4":   re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "url":    re.compile(r"https?://[^\s\"'<>]{4,200}", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cc|ru|cn|top|xyz|tk|pw|info)\b",
        re.IGNORECASE
    ),
    "email":  re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
}

# ─── YARA rules ───────────────────────────────────────────────────────────────

YARA_RULES_SOURCE = """
rule suspicious_dropper {
    meta:
        description = "APK dropper pattern — loads external DEX"
        severity = "HIGH"
    strings:
        $a = "DexClassLoader" ascii
        $b = "loadDex" ascii
        $c = "PathClassLoader" ascii
    condition:
        any of them
}

rule c2_hardcoded_url {
    meta:
        description = "Hardcoded C2 URL pattern"
        severity = "HIGH"
    strings:
        $a = /https?:\\/\\/[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/ ascii wide
    condition:
        $a
}

rule sms_stealer {
    meta:
        description = "SMS reading + sending combination"
        severity = "CRITICAL"
    strings:
        $a = "READ_SMS" ascii
        $b = "sendTextMessage" ascii
        $c = "getMessageBody" ascii
    condition:
        2 of them
}

rule keylogger_indicator {
    meta:
        description = "Accessibility service abuse (keylogger pattern)"
        severity = "HIGH"
    strings:
        $a = "AccessibilityService" ascii
        $b = "onAccessibilityEvent" ascii
        $c = "TYPE_VIEW_TEXT_CHANGED" ascii
    condition:
        2 of them
}

rule banking_trojan {
    meta:
        description = "Overlay attack pattern common in banking trojans"
        severity = "CRITICAL"
    strings:
        $a = "SYSTEM_ALERT_WINDOW" ascii
        $b = "TYPE_APPLICATION_OVERLAY" ascii
        $c = "WindowManager.LayoutParams" ascii
    condition:
        2 of them
}
"""


class StaticAnalyzer:
    """
    Full static analysis pipeline for a single APK.
    Usage:
        analyzer = StaticAnalyzer("malware.apk")
        results  = analyzer.run()
    """

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.results: dict = {}

    def run(self) -> dict:
        print(f"[*] Starting static analysis: {self.apk_path.name}")
        self.results = {
            "meta":        self._extract_meta(),
            "permissions": self._extract_permissions(),
            "apis":        self._extract_suspicious_apis(),
            "iocs":        self._extract_iocs(),
            "yara":        self._run_yara(),
            "certificate": self._extract_certificate(),
            "risk_score":  0,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        }
        self.results["risk_score"] = self._compute_risk_score()
        print(f"[+] Static analysis complete. Risk score: {self.results['risk_score']}/100")
        return self.results

    def _extract_meta(self) -> dict:
        print("[*] Extracting APK metadata...")
        apk, _, _ = AnalyzeAPK(str(self.apk_path))
        sha256 = hashlib.sha256(self.apk_path.read_bytes()).hexdigest()
        return {
            "filename":            self.apk_path.name,
            "sha256":              sha256,
            "file_size":           self.apk_path.stat().st_size,
            "package":             apk.get_package(),
            "app_name":            apk.get_app_name(),
            "version":             apk.get_androidversion_name(),
            "min_sdk":             apk.get_min_sdk_version(),
            "target_sdk":          apk.get_target_sdk_version(),
            "declared_activities": len(apk.get_activities()),
            "declared_services":   len(apk.get_services()),
            "declared_receivers":  len(apk.get_receivers()),
        }

    def _extract_permissions(self) -> dict:
        print("[*] Analysing permissions...")
        apk, _, _ = AnalyzeAPK(str(self.apk_path))
        all_perms = apk.get_permissions()
        flagged = [
            {"permission": p, "risk": DANGEROUS_PERMISSIONS[p]}
            for p in all_perms if p in DANGEROUS_PERMISSIONS
        ]
        return {"total": len(all_perms), "flagged": flagged, "all": all_perms}

    def _extract_suspicious_apis(self) -> list:
        print("[*] Scanning for suspicious API calls...")
        _, _, dx = AnalyzeAPK(str(self.apk_path))
        found = []
        for api_str, description in SUSPICIOUS_APIS.items():
            for method in dx.get_methods():
                if api_str in str(method):
                    found.append({
                        "api":         api_str,
                        "description": description,
                        "location":    str(method),
                    })
                    break
        return found

    def _extract_iocs(self) -> dict:
        print("[*] Extracting IOCs (IPs, URLs, domains)...")
        iocs: dict = {"ips": [], "urls": [], "domains": [], "emails": []}
        key_map = {"ipv4": "ips", "url": "urls", "domain": "domains", "email": "emails"}
        with zipfile.ZipFile(str(self.apk_path), "r") as zf:
            for name in zf.namelist():
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    for key, pattern in PATTERNS.items():
                        target = key_map[key]
                        for m in pattern.findall(content):
                            if m not in iocs[target]:
                                iocs[target].append(m)
                except Exception:
                    continue
        for k in iocs:
            iocs[k] = list(set(iocs[k]))[:50]
        return iocs

    def _run_yara(self) -> list:
        print("[*] Running YARA rules...")
        rules = yara.compile(source=YARA_RULES_SOURCE)
        hits = []
        with zipfile.ZipFile(str(self.apk_path), "r") as zf:
            for name in zf.namelist():
                try:
                    data = zf.read(name)
                    for m in rules.match(data=data):
                        hits.append({
                            "rule":        m.rule,
                            "severity":    m.meta.get("severity", "MEDIUM"),
                            "description": m.meta.get("description", ""),
                            "file":        name,
                        })
                except Exception:
                    continue
        return hits

    def _extract_certificate(self) -> Optional[dict]:
        print("[*] Extracting certificate info...")
        try:
            apk, _, _ = AnalyzeAPK(str(self.apk_path))
            certs = apk.get_certificates()
            if not certs:
                return None
            cert = certs[0]
            return {
                "issuer":      str(cert.issuer.human_friendly),
                "subject":     str(cert.subject.human_friendly),
                "serial":      str(cert.serial_number),
                "not_before":  str(cert.not_valid_before),
                "not_after":   str(cert.not_valid_after),
                "self_signed": cert.issuer == cert.subject,
            }
        except Exception as e:
            return {"error": str(e)}

    def _compute_risk_score(self) -> int:
        score = 0
        score += min(len(self.results["permissions"]["flagged"]) * 3, 30)
        score += min(len(self.results["apis"]) * 2, 25)
        ioc_count = sum(len(v) for v in self.results["iocs"].values())
        score += min(ioc_count * 2, 20)
        yara_score = 0
        for hit in self.results["yara"]:
            if hit["severity"] == "CRITICAL":
                yara_score += 10
            elif hit["severity"] == "HIGH":
                yara_score += 5
            else:
                yara_score += 2
        score += min(yara_score, 25)
        return min(score, 100)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python static_analyzer.py <path/to/app.apk>")
        sys.exit(1)
    analyzer = StaticAnalyzer(sys.argv[1])
    results  = analyzer.run()
    out_file = Path(sys.argv[1]).stem + "_static_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {out_file}")
