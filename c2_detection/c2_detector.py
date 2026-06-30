"""
DroidScan — Module 3: C2 Detection + ML Risk Classifier
=========================================================
Combines static + dynamic results to:
  - Check IPs/domains against AbuseIPDB and VirusTotal
  - Detect C2 patterns using heuristics
  - Score APK maliciousness using a trained ML classifier
  - Map detected behaviors to MITRE ATT&CK for Mobile

Dependencies:
    pip install scikit-learn requests joblib

API keys (free tier sufficient):
    ABUSEIPDB_KEY  — https://www.abuseipdb.com/register
    VIRUSTOTAL_KEY — https://www.virustotal.com/gui/join-us
"""

import os
import json
import time
import joblib
import requests
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional
from sklearn.ensemble import RandomForestClassifier


# ─── API config ───────────────────────────────────────────────────────────────

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY",  "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"


# ─── MITRE ATT&CK for Mobile mappings ────────────────────────────────────────

MITRE_MAPPINGS = {
    "getDeviceId":            ("T1418", "Application Discovery",              "Discovery"),
    "getInstalledPackages":   ("T1418", "Application Discovery",              "Discovery"),
    "getCellLocation":        ("T1430", "Location Tracking",                  "Collection"),
    "getSubscriberId":        ("T1422", "System Network Config Discovery",    "Discovery"),
    "READ_SMS":               ("T1412", "Capture SMS Messages",               "Collection"),
    "READ_CONTACTS":          ("T1432", "Access Contact List",                "Collection"),
    "RECORD_AUDIO":           ("T1429", "Capture Audio",                      "Collection"),
    "CAMERA":                 ("T1512", "Video Capture",                      "Collection"),
    "READ_CALL_LOG":          ("T1433", "Access Call Log",                    "Collection"),
    "HttpURLConnection":      ("T1437", "Standard Application Layer Protocol","C2"),
    "c2_hardcoded_url":       ("T1437", "Hardcoded C2 Endpoint",              "C2"),
    "Runtime.exec":           ("T1603", "Scheduled Task/Job",                 "Execution"),
    "DexClassLoader":         ("T1407", "Download New Code at Runtime",       "Execution"),
    "SHELL_EXEC":             ("T1603", "Shell Execution",                    "Execution"),
    "RECEIVE_BOOT_COMPLETED": ("T1402", "Boot or Logon Autostart",           "Persistence"),
    "BIND_DEVICE_ADMIN":      ("T1401", "Device Administrator Permissions",  "Privilege Escalation"),
    "Base64.decode":          ("T1406", "Obfuscated Files or Information",   "Defense Evasion"),
    "javax.crypto":           ("T1521", "Encrypted Channel",                 "Defense Evasion"),
    "sendTextMessage":        ("T1582", "SMS Control",                       "Impact"),
    "SEND_SMS":               ("T1582", "SMS Control",                       "Impact"),
}

# ─── C2 heuristics ────────────────────────────────────────────────────────────

def _detect_beaconing(events: dict, threshold: int = 3) -> bool:
    host_counts: dict = {}
    for r in events.get("network_traffic", []):
        host = r.get("host", "")
        host_counts[host] = host_counts.get(host, 0) + 1
    return any(v >= threshold for v in host_counts.values())


C2_HEURISTICS = [
    {
        "id":          "C2-001",
        "name":        "Hardcoded IP communication",
        "description": "App communicates directly with an IP address (no domain)",
        "check":       lambda iocs, events: len(iocs.get("ips", [])) > 0,
        "severity":    "HIGH",
    },
    {
        "id":          "C2-002",
        "name":        "Non-standard port usage",
        "description": "HTTP traffic on unusual ports (not 80/443)",
        "check":       lambda iocs, events: any(
            r.get("port") not in (80, 443, None)
            for r in events.get("network_traffic", [])
        ),
        "severity":    "HIGH",
    },
    {
        "id":          "C2-003",
        "name":        "Beaconing pattern",
        "description": "Repeated HTTP requests to same host at regular intervals",
        "check":       lambda iocs, events: _detect_beaconing(events),
        "severity":    "CRITICAL",
    },
    {
        "id":          "C2-004",
        "name":        "Data exfiltration (large POST)",
        "description": "HTTP POST with large body — possible data upload to C2",
        "check":       lambda iocs, events: any(
            r.get("method") == "POST" and len(r.get("body", "")) > 200
            for r in events.get("network_traffic", [])
        ),
        "severity":    "CRITICAL",
    },
    {
        "id":          "C2-005",
        "name":        "Dynamic code loading over network",
        "description": "DEX_LOAD event combined with network activity",
        "check":       lambda iocs, events: (
            any(e["type"] == "DEX_LOAD" for e in events.get("frida_events", []))
            and len(events.get("network_traffic", [])) > 0
        ),
        "severity":    "CRITICAL",
    },
]


# ─── Threat intel ─────────────────────────────────────────────────────────────

class ThreatIntel:

    def check_ip(self, ip: str) -> dict:
        if not ABUSEIPDB_KEY:
            return {"ip": ip, "is_malicious": False, "note": "no API key"}
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            data = resp.json().get("data", {})
            return {
                "ip":            ip,
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "country":       data.get("countryCode", ""),
                "isp":           data.get("isp", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
                "is_malicious":  data.get("abuseConfidenceScore", 0) >= 25,
            }
        except Exception as e:
            return {"ip": ip, "error": str(e), "is_malicious": False}

    def check_domain(self, domain: str) -> dict:
        if not VIRUSTOTAL_KEY:
            return {"domain": domain, "is_malicious": False, "note": "no API key"}
        try:
            resp = requests.get(
                f"{VIRUSTOTAL_URL}/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=5,
            )
            stats = (resp.json()
                     .get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
            malicious = stats.get("malicious", 0)
            return {
                "domain":      domain,
                "malicious":   malicious,
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "is_malicious": malicious >= 2,
            }
        except Exception as e:
            return {"domain": domain, "error": str(e), "is_malicious": False}

    def bulk_check(self, iocs: dict) -> dict:
        results: dict = {"ips": [], "domains": []}
        for ip in iocs.get("ips", [])[:10]:
            results["ips"].append(self.check_ip(ip))
            time.sleep(0.5)
        for domain in iocs.get("domains", [])[:10]:
            results["domains"].append(self.check_domain(domain))
            time.sleep(0.5)
        return results


# ─── Feature extraction ───────────────────────────────────────────────────────

FEATURE_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
    "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG",
    "PROCESS_OUTGOING_CALLS", "RECEIVE_BOOT_COMPLETED",
    "WRITE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES",
    "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW",
]

FEATURE_APIS = [
    "getDeviceId", "getSubscriberId", "sendTextMessage",
    "execShell", "Runtime.exec", "DexClassLoader",
    "loadLibrary", "getInstalledPackages", "HttpURLConnection",
    "javax.crypto", "Base64.decode",
]

# Total features = 14 perms + 11 apis + 5 extra = 30
FEATURE_NAMES = (
    FEATURE_PERMISSIONS + FEATURE_APIS +
    ["ip_count", "url_count", "domain_count", "yara_critical", "yara_high"]
)


def build_feature_vector(static_results: dict) -> np.ndarray:
    """Convert static analysis results into a 30-dim numeric feature vector."""
    perms     = [p["permission"] for p in
                 static_results.get("permissions", {}).get("flagged", [])]
    apis      = [a["api"] for a in static_results.get("apis", [])]
    iocs      = static_results.get("iocs", {})
    yara_hits = static_results.get("yara", [])

    features = []

    # 14 binary permission features
    for p in FEATURE_PERMISSIONS:
        features.append(1 if any(p in perm for perm in perms) else 0)

    # 11 binary API features
    for a in FEATURE_APIS:
        features.append(1 if any(a in api for api in apis) else 0)

    # 3 IOC count features
    features.append(min(len(iocs.get("ips",     [])), 20))
    features.append(min(len(iocs.get("urls",    [])), 20))
    features.append(min(len(iocs.get("domains", [])), 20))

    # 2 YARA severity counts
    features.append(sum(1 for h in yara_hits if h.get("severity") == "CRITICAL"))
    features.append(sum(1 for h in yara_hits if h.get("severity") == "HIGH"))

    assert len(features) == 30, f"Feature vector length mismatch: {len(features)}"
    return np.array(features, dtype=float)


# ─── Shared verdict thresholds ────────────────────────────────────────────────
# Single source of truth for score -> label mapping. Used by the ML classifier
# (as a standalone signal) and by the final blended score in C2Detector.run()
# and tasks.py, so the whole pipeline can't disagree with itself on what
# "MALICIOUS" / "SUSPICIOUS" / "BENIGN" means at a given score.

MALICIOUS_THRESHOLD  = 70
SUSPICIOUS_THRESHOLD = 40


def score_to_label(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "BENIGN"


# ─── ML classifier ────────────────────────────────────────────────────────────

class MLClassifier:

    MODEL_PATH = Path(__file__).parent / "droidscan_rf_model.joblib"

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        if self.MODEL_PATH.exists():
            self.model = joblib.load(self.MODEL_PATH)
            print("[+] ML model loaded from disk")

    def train(self, samples: list, labels: list):
        print(f"[*] Training ML model on {len(samples)} samples...")
        X = np.array([build_feature_vector(s) for s in samples])
        y = np.array(labels)
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=12,
            min_samples_leaf=2, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )
        self.model.fit(X, y)
        joblib.dump(self.model, self.MODEL_PATH)
        print(f"[+] Model saved to {self.MODEL_PATH}")

    def predict(self, static_results: dict) -> dict:
        if self.model is None:
            score = static_results.get("risk_score", 0)
            label = score_to_label(score)
            return {"ml_score": score, "label": label, "source": "heuristic_fallback"}

        features = build_feature_vector(static_results).reshape(1, -1)
        prob  = self.model.predict_proba(features)[0][1]
        score = int(prob * 100)
        label = score_to_label(score)
        return {
            "ml_score": score,
            "label":    label,
            "source":   "random_forest",
            "features": dict(zip(FEATURE_NAMES,
                                 build_feature_vector(static_results).tolist())),
        }


# ─── Main C2 + MITRE engine ───────────────────────────────────────────────────

class C2Detector:

    def __init__(self):
        self.intel      = ThreatIntel()
        self.classifier = MLClassifier()

    def run(self, static_results: dict, dynamic_results: dict) -> dict:
        print("[*] Running C2 detection and risk analysis...")
        iocs         = static_results.get("iocs", {})
        c2_hits      = self._run_heuristics(iocs, dynamic_results)
        threat_intel = self.intel.bulk_check(iocs)
        mitre_tags   = self._build_mitre_tags(static_results, dynamic_results)
        ml_result    = self.classifier.predict(static_results)
        final_score  = self._final_score(
            static_results.get("risk_score", 0),
            ml_result["ml_score"],
            threat_intel, c2_hits,
        )
        # verdict reflects the blended final_score, NOT ml_result["label"]
        # (ml_result["label"] is the ML model's standalone opinion and is kept
        # in the response for transparency, but is not the pipeline's verdict)
        verdict = score_to_label(final_score)
        print(f"[+] C2 analysis done. Final score: {final_score}/100  Verdict: {verdict}")
        return {
            "c2_indicators": c2_hits,
            "threat_intel":  threat_intel,
            "mitre_tags":    mitre_tags,
            "ml_result":     ml_result,
            "final_score":   final_score,
            "verdict":       verdict,
            "timestamp":     datetime.utcnow().isoformat() + "Z",
        }

    def _run_heuristics(self, iocs: dict, dynamic_results: dict) -> list:
        hits = []
        for h in C2_HEURISTICS:
            try:
                if h["check"](iocs, dynamic_results):
                    hits.append({
                        "id":          h["id"],
                        "name":        h["name"],
                        "description": h["description"],
                        "severity":    h["severity"],
                    })
            except Exception:
                continue
        return hits

    def _build_mitre_tags(self, static: dict, dynamic: dict) -> list:
        tags: dict = {}
        seen: set  = set()

        sources = (
            [p["permission"].split(".")[-1]
             for p in static.get("permissions", {}).get("flagged", [])] +
            [a["api"] for a in static.get("apis", [])] +
            [y["rule"] for y in static.get("yara", [])] +
            [e["type"] for e in dynamic.get("frida_events", [])]
        )
        for key in sources:
            if key in MITRE_MAPPINGS and key not in seen:
                tid, name, tactic = MITRE_MAPPINGS[key]
                tags[tid] = {"technique_id": tid, "name": name, "tactic": tactic}
                seen.add(key)

        return list(tags.values())

    def _final_score(self, static_score: int, ml_score: int,
                     threat_intel: dict, c2_hits: list) -> int:
        score = int(static_score * 0.3 + ml_score * 0.4)
        malicious_hosts = (
            sum(1 for r in threat_intel.get("ips",     []) if r.get("is_malicious")) +
            sum(1 for r in threat_intel.get("domains", []) if r.get("is_malicious"))
        )
        score += min(malicious_hosts * 10, 20)
        for h in c2_hits:
            if h["severity"] == "CRITICAL":
                score += 5
        return min(score, 100)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python c2_detector.py <static_results.json> <dynamic_results.json>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        static = json.load(f)
    with open(sys.argv[2]) as f:
        dynamic = json.load(f)
    detector = C2Detector()
    results  = detector.run(static, dynamic)
    with open("c2_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] C2 results saved to c2_results.json")
