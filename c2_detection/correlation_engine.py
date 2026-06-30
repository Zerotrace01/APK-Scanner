"""
DroidScan — Correlation Engine
================================
Explicitly ties cross-signal findings into named attack patterns.
Answers the "Behavioural Correlation" requirement:
  "Surface indicators must be tied to observed runtime behaviour
   and network activity."

Each pattern checks static + dynamic + C2 signals together,
building a full evidence chain for investigators.

Usage:
    engine  = CorrelationEngine()
    results = engine.run(static_results, dynamic_results, c2_results)
"""

from datetime import datetime
from typing import Tuple


# ─── Signal helpers ───────────────────────────────────────────────────────────

def _has_permission(static: dict, perm: str) -> Tuple[bool, str]:
    flagged = [p["permission"] for p in
               static.get("permissions", {}).get("flagged", [])]
    found = any(perm in p for p in flagged)
    return found, (f"Permission declared: {perm}" if found else "")


def _has_api(static: dict, api: str) -> Tuple[bool, str]:
    found = any(api in a["api"] for a in static.get("apis", []))
    return found, (f"Suspicious API detected: {api}" if found else "")


def _has_frida_event(dynamic: dict, etype: str) -> Tuple[bool, str]:
    events = dynamic.get("frida_events", [])
    match  = next((e for e in events if e["type"] == etype), None)
    if match:
        data = str(match.get("data", ""))[:80]
        return True, f"Runtime event captured: {etype} -> {data}"
    return False, ""


def _has_yara(static: dict, rule: str) -> Tuple[bool, str]:
    found = any(y["rule"] == rule for y in static.get("yara", []))
    return found, (f"YARA rule matched: {rule}" if found else "")


def _has_network_post(dynamic: dict, min_body: int = 100) -> Tuple[bool, str]:
    for r in dynamic.get("network_traffic", []):
        if r.get("method") == "POST" and len(r.get("body", "")) >= min_body:
            return True, f"Large HTTP POST to {r.get('host', '?')} ({len(r['body'])} bytes)"
    return False, ""


def _has_network_to_ip(dynamic: dict) -> Tuple[bool, str]:
    import re
    ip_pat = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    for r in dynamic.get("network_traffic", []):
        host = r.get("host", "")
        if ip_pat.match(host):
            return True, f"Direct IP communication: {host}"
    return False, ""


def _has_malicious_host(c2: dict) -> Tuple[bool, str]:
    intel = c2.get("threat_intel", {})
    for r in intel.get("ips", []):
        if r.get("is_malicious"):
            return (True,
                    f"Confirmed malicious IP: {r.get('ip')} "
                    f"(AbuseIPDB score: {r.get('abuse_score')}%)")
    for r in intel.get("domains", []):
        if r.get("is_malicious"):
            return (True,
                    f"Confirmed malicious domain: {r.get('domain')} "
                    f"({r.get('malicious')} VT detections)")
    return False, ""


def _has_beaconing(dynamic: dict, threshold: int = 3) -> Tuple[bool, str]:
    from collections import Counter
    hosts  = [r.get("host", "") for r in dynamic.get("network_traffic", [])]
    counts = Counter(hosts)
    for host, cnt in counts.items():
        if cnt >= threshold and host:
            return True, f"Beaconing pattern: {host} contacted {cnt} times"
    return False, ""


def _has_iocs(static: dict, ioc_type: str, min_count: int = 1) -> Tuple[bool, str]:
    items = static.get("iocs", {}).get(ioc_type, [])
    if len(items) >= min_count:
        return True, f"Hardcoded {ioc_type}: {', '.join(items[:3])}"
    return False, ""


# ─── Attack pattern library ───────────────────────────────────────────────────

def build_patterns() -> list:
    return [
        {
            "id":          "PAT-001",
            "name":        "SMS Stealer / OTP Interceptor",
            "severity":    "CRITICAL",
            "description": (
                "App reads incoming SMS messages (likely OTP interception) "
                "and exfiltrates content to a remote server."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_permission(s, "READ_SMS"),
                lambda s, d, c: _has_permission(s, "RECEIVE_SMS"),
                lambda s, d, c: _has_frida_event(d, "SMS_SEND"),
                lambda s, d, c: _has_api(s, "sendTextMessage"),
                lambda s, d, c: _has_yara(s, "sms_stealer"),
                lambda s, d, c: _has_network_post(d, min_body=50),
            ],
            "mitre": ["T1412 - Capture SMS Messages",
                      "T1437 - Standard App Layer Protocol"],
        },
        {
            "id":          "PAT-002",
            "name":        "Banking Trojan / Overlay Attack",
            "severity":    "CRITICAL",
            "description": (
                "App draws overlay windows on top of banking apps to steal "
                "credentials. Uses Accessibility Service for keylogging."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_permission(s, "SYSTEM_ALERT_WINDOW"),
                lambda s, d, c: _has_yara(s, "banking_trojan"),
                lambda s, d, c: _has_yara(s, "keylogger_indicator"),
                lambda s, d, c: _has_permission(s, "BIND_DEVICE_ADMIN"),
                lambda s, d, c: _has_api(s, "TelephonyManager"),
            ],
            "mitre": ["T1417 - Input Capture",
                      "T1409 - Stored Application Data"],
        },
        {
            "id":          "PAT-003",
            "name":        "Spyware / Device Surveillance",
            "severity":    "CRITICAL",
            "description": (
                "App silently collects device identifiers, location, "
                "contacts, and call logs, then uploads to a remote server."
            ),
            "min_hits": 3,
            "signals": [
                lambda s, d, c: _has_frida_event(d, "DEVICE_ID_READ"),
                lambda s, d, c: _has_frida_event(d, "IMSI_READ"),
                lambda s, d, c: _has_permission(s, "ACCESS_FINE_LOCATION"),
                lambda s, d, c: _has_permission(s, "READ_CONTACTS"),
                lambda s, d, c: _has_permission(s, "READ_CALL_LOG"),
                lambda s, d, c: _has_network_post(d, min_body=100),
            ],
            "mitre": ["T1422 - System Network Config Discovery",
                      "T1430 - Location Tracking",
                      "T1432 - Access Contact List"],
        },
        {
            "id":          "PAT-004",
            "name":        "C2 Beacon / Remote Access Trojan",
            "severity":    "CRITICAL",
            "description": (
                "App maintains persistent communication with a C2 server, "
                "receiving commands and exfiltrating data at regular intervals."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_beaconing(d),
                lambda s, d, c: _has_malicious_host(c),
                lambda s, d, c: _has_network_to_ip(d),
                lambda s, d, c: _has_iocs(s, "ips", min_count=1),
                lambda s, d, c: _has_network_post(d),
            ],
            "mitre": ["T1437 - Standard App Layer Protocol",
                      "T1521 - Encrypted Channel"],
        },
        {
            "id":          "PAT-005",
            "name":        "APK Dropper / Dynamic Code Loader",
            "severity":    "HIGH",
            "description": (
                "App downloads and executes additional code at runtime, "
                "bypassing static analysis and app store review."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_frida_event(d, "DEX_LOAD"),
                lambda s, d, c: _has_yara(s, "suspicious_dropper"),
                lambda s, d, c: _has_api(s, "DexClassLoader"),
                lambda s, d, c: _has_network_post(d),
            ],
            "mitre": ["T1407 - Download New Code at Runtime"],
        },
        {
            "id":          "PAT-006",
            "name":        "Boot Persistence / Auto-Start Malware",
            "severity":    "HIGH",
            "description": (
                "App registers to start automatically on device boot, "
                "ensuring persistence even after the user closes it."
            ),
            "min_hits": 1,
            "signals": [
                lambda s, d, c: _has_permission(s, "RECEIVE_BOOT_COMPLETED"),
                lambda s, d, c: _has_api(s, "getInstalledPackages"),
            ],
            "mitre": ["T1402 - Boot or Logon Autostart"],
        },
        {
            "id":          "PAT-007",
            "name":        "Data Exfiltration via Encrypted Channel",
            "severity":    "HIGH",
            "description": (
                "App encrypts harvested data before transmitting, "
                "making traffic inspection difficult."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_frida_event(d, "CRYPTO_KEY_GEN"),
                lambda s, d, c: _has_api(s, "javax.crypto"),
                lambda s, d, c: _has_api(s, "Base64.decode"),
                lambda s, d, c: _has_network_post(d, min_body=50),
            ],
            "mitre": ["T1521 - Encrypted Channel",
                      "T1406 - Obfuscated Files or Information"],
        },
        {
            "id":          "PAT-008",
            "name":        "Microphone / Camera Surveillance",
            "severity":    "HIGH",
            "description": (
                "App accesses microphone or camera without clear "
                "user-facing purpose, indicating potential covert surveillance."
            ),
            "min_hits": 2,
            "signals": [
                lambda s, d, c: _has_permission(s, "RECORD_AUDIO"),
                lambda s, d, c: _has_permission(s, "CAMERA"),
                lambda s, d, c: _has_network_post(d, min_body=200),
            ],
            "mitre": ["T1429 - Capture Audio", "T1512 - Video Capture"],
        },
    ]


# ─── Engine ───────────────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Runs all attack patterns against combined static + dynamic + C2 results.
    Returns confirmed patterns with full evidence chains.
    """

    def run(self, static: dict, dynamic: dict, c2: dict) -> dict:
        print("[*] Running correlation engine...")
        patterns  = build_patterns()
        confirmed = []
        partial   = []

        for pat in patterns:
            hits     = []
            evidence = []

            for signal_fn in pat["signals"]:
                try:
                    matched, ev = signal_fn(static, dynamic, c2)
                    hits.append(matched)
                    if matched and ev:
                        evidence.append(ev)
                except Exception:
                    hits.append(False)

            hit_count = sum(hits)
            total     = len(pat["signals"])
            result    = {
                "id":             pat["id"],
                "name":           pat["name"],
                "severity":       pat["severity"],
                "description":    pat["description"],
                "mitre":          pat["mitre"],
                "signals_hit":    hit_count,
                "signals_total":  total,
                "evidence":       evidence,
                "confidence":     round(hit_count / total * 100) if total else 0,
            }

            if hit_count >= pat["min_hits"]:
                result["status"] = "CONFIRMED"
                confirmed.append(result)
                print(f"  [!] {pat['id']} CONFIRMED: {pat['name']} "
                      f"({hit_count}/{total} signals)")
            elif hit_count > 0:
                result["status"] = "PARTIAL"
                partial.append(result)

        print(f"[+] Correlation: {len(confirmed)} confirmed, {len(partial)} partial")
        return {
            "confirmed":       confirmed,
            "partial":         partial,
            "total_confirmed": len(confirmed),
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }
