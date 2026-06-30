"""
DroidScan — Obfuscation Detector
==================================
Detects code obfuscation techniques commonly used by malware to evade
static analysis and app store review.

Checks:
  1. Class name entropy    — short/meaningless names like a.b.c, A1, x
  2. String encryption    — Base64-encoded strings, high-entropy constants
  3. Reflection usage     — dynamic method invocation to hide API calls
  4. Native code loading  — .so libraries that can hide malicious logic
  5. Resource obfuscation — assets with misleading extensions

Dependencies:
    pip install androguard
"""

import re
import math
import zipfile
from pathlib import Path

from androguard.misc import AnalyzeAPK


# ─── Helpers ──────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy (higher = more random/encrypted)."""
    if not data:
        return 0.0
    freq: dict = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length  = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_obfuscated_name(name: str) -> bool:
    """Returns True if a class/method name looks obfuscated."""
    parts = name.replace("/", ".").split(".")
    leaf  = parts[-1] if parts else name
    if len(leaf) <= 2:
        return True
    if len(leaf) <= 4 and leaf.lower() == leaf:
        return True
    if re.match(r"^[a-zA-Z]{1,3}\d+$", leaf):
        return True
    return False


class ObfuscationDetector:
    """
    Full obfuscation analysis pipeline for one APK.

    Usage:
        detector = ObfuscationDetector("malware.apk")
        result   = detector.run()
    """

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self._apk = None
        self._dex = None

    def _load(self):
        if self._apk is None:
            apk, _, dx = AnalyzeAPK(str(self.apk_path))
            self._apk = apk
            self._dex = dx

    # ── 1. Class name obfuscation ─────────────────────────────────────────────

    def check_class_names(self) -> dict:
        """Ratio of obfuscated class names to total — ProGuard/R8 indicator."""
        self._load()
        total = obfuscated = 0
        examples = []
        for cls in self._dex.get_classes():
            name = cls.name.strip("L;").replace("/", ".")
            total += 1
            if is_obfuscated_name(name):
                obfuscated += 1
                if len(examples) < 5:
                    examples.append(name)
        ratio = obfuscated / total if total > 0 else 0
        score = min(int(ratio * 100), 40)
        detail = (
            f"{obfuscated}/{total} classes have obfuscated names "
            f"({ratio*100:.1f}%) — consistent with ProGuard/DexGuard"
            if ratio > 0.3
            else f"{obfuscated}/{total} classes obfuscated ({ratio*100:.1f}%) — low"
        )
        return {
            "check":      "class_name_obfuscation",
            "total":      total,
            "obfuscated": obfuscated,
            "ratio":      round(ratio, 3),
            "score":      score,
            "examples":   examples,
            "detail":     detail,
        }

    # ── 2. High-entropy string detection ─────────────────────────────────────

    def check_string_entropy(self) -> dict:
        """Scans string literals for high-entropy / Base64 encoded values."""
        self._load()
        high_entropy = []
        b64_pattern  = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
        for cls in self._dex.get_classes():
            for method in cls.get_methods():
                try:
                    code = method.get_code()
                    if not code:
                        continue
                    for ins in code.get_bc().get_instructions():
                        if ins.get_name() in ("const-string", "const-string/jumbo"):
                            val = ins.get_output().strip("'\" ")
                            if len(val) < 8:
                                continue
                            ent = shannon_entropy(val)
                            if ent > 4.5 or b64_pattern.match(val):
                                high_entropy.append({
                                    "value":   val[:60] + ("..." if len(val) > 60 else ""),
                                    "entropy": ent,
                                    "is_b64":  bool(b64_pattern.match(val)),
                                })
                except Exception:
                    continue
        count = len(high_entropy)
        score = min(count * 3, 25)
        detail = (
            f"{count} high-entropy strings detected — possible encrypted payloads or C2 addresses"
            if count > 0
            else "No high-entropy strings detected"
        )
        return {
            "check":                 "string_entropy",
            "high_entropy_strings":  count,
            "score":                 score,
            "examples":              high_entropy[:5],
            "detail":                detail,
        }

    # ── 3. Reflection usage ───────────────────────────────────────────────────

    def check_reflection(self) -> dict:
        """Detects Java reflection used to hide API calls from static analysis."""
        self._load()
        reflection_apis = [
            "java/lang/Class;->forName",
            "java/lang/reflect/Method;->invoke",
            "java/lang/ClassLoader;->loadClass",
            "getDeclaredMethod",
            "getMethod(",
        ]
        hits = []
        for cls in self._dex.get_classes():
            for method in cls.get_methods():
                try:
                    src = str(method.get_source() or "")
                    for api in reflection_apis:
                        if api in src and api not in hits:
                            hits.append(api)
                except Exception:
                    continue
        score  = min(len(hits) * 5, 20)
        detail = (
            f"Reflection detected: {', '.join(hits[:3])} — "
            "API calls may be hidden from static analysis"
            if hits
            else "No reflection detected"
        )
        return {
            "check":           "reflection_usage",
            "reflection_apis": hits,
            "score":           score,
            "detail":          detail,
        }

    # ── 4. Native library loading ─────────────────────────────────────────────

    def check_native_libs(self) -> dict:
        """Native .so libraries can contain obfuscated C/C++ malicious logic."""
        libs = []
        suspicious = []
        with zipfile.ZipFile(str(self.apk_path), "r") as zf:
            for name in zf.namelist():
                if name.endswith(".so"):
                    libs.append(name)
                    lib_name = name.split("/")[-1]
                    if not lib_name.startswith("lib") or len(lib_name) < 8:
                        suspicious.append(name)
        score  = min(len(libs) * 3 + len(suspicious) * 5, 15)
        detail = (
            f"{len(libs)} native libraries found"
            + (f", {len(suspicious)} with suspicious names" if suspicious else "")
            + " — native code cannot be fully statically analysed"
            if libs
            else "No native libraries found"
        )
        return {
            "check":      "native_libraries",
            "lib_count":  len(libs),
            "suspicious": suspicious,
            "all_libs":   libs,
            "score":      score,
            "detail":     detail,
        }

    # ── 5. Resource obfuscation ───────────────────────────────────────────────

    def check_resource_obfuscation(self) -> dict:
        """Detects assets/resources with misleading file extensions."""
        suspicious = []
        magic_bytes = {
            b"PK\x03\x04":        "ZIP/APK",
            b"dex\n":             "DEX",
            b"MZ":                "Windows PE",
            b"\x7fELF":          "ELF binary",
            b"\xca\xfe\xba\xbe": "Java class",
        }
        with zipfile.ZipFile(str(self.apk_path), "r") as zf:
            for name in zf.namelist():
                if not (name.startswith("assets/") or name.startswith("res/")):
                    continue
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext in ("png", "jpg", "jpeg", "gif", "xml", "json", "txt"):
                    try:
                        data = zf.read(name)[:8]
                        for magic, ftype in magic_bytes.items():
                            if data.startswith(magic):
                                suspicious.append({
                                    "file":         name,
                                    "declared_ext": ext,
                                    "actual_type":  ftype,
                                })
                    except Exception:
                        continue
        score  = min(len(suspicious) * 10, 15)
        detail = (
            f"{len(suspicious)} resources have mismatched file types — possible hidden payloads"
            if suspicious
            else "No resource obfuscation detected"
        )
        return {
            "check":      "resource_obfuscation",
            "suspicious": suspicious,
            "score":      score,
            "detail":     detail,
        }

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> dict:
        print("[*] Running obfuscation detection...")
        checks: dict = {}
        for name, fn in [
            ("class_names", self.check_class_names),
            ("strings",     self.check_string_entropy),
            ("reflection",  self.check_reflection),
            ("native_libs", self.check_native_libs),
            ("resources",   self.check_resource_obfuscation),
        ]:
            try:
                checks[name] = fn()
            except Exception as e:
                checks[name] = {"check": name, "score": 0, "error": str(e),
                                "detail": f"Check failed: {e}"}

        total_score = min(sum(c.get("score", 0) for c in checks.values()), 100)
        level = (
            "HEAVY"    if total_score >= 70 else
            "MODERATE" if total_score >= 40 else
            "LIGHT"    if total_score >= 15 else
            "NONE"
        )
        summary = (
            "Heavy obfuscation detected — malware likely uses multiple evasion techniques"
            if level == "HEAVY" else
            "Moderate obfuscation — some code hiding techniques present"
            if level == "MODERATE" else
            "Light obfuscation — minimal code hiding"
            if level == "LIGHT" else
            "No significant obfuscation detected"
        )
        print(f"[+] Obfuscation score: {total_score}/100 — {level}")
        return {
            "obfuscation_score": total_score,
            "obfuscation_level": level,
            "checks":            checks,
            "summary":           summary,
        }


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python obfuscation_detector.py <path/to/app.apk>")
        sys.exit(1)
    detector = ObfuscationDetector(sys.argv[1])
    result   = detector.run()
    out = Path(sys.argv[1]).stem + "_obfuscation.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Saved to {out}")
