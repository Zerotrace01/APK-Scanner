"""
DroidScan — ML Model Training Script
======================================
Downloads labeled APK samples, extracts features, trains a
Random Forest classifier, evaluates it, and saves the model.

Run this ONCE before hackathon day.
Model saved to: c2_detection/droidscan_rf_model.joblib

Usage:
    python train_model.py --samples 500 --output c2_detection/
"""

import os
import json
import time
import argparse
import zipfile
import requests
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ── Resolve paths so imports work from any CWD ────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))
from static_analysis.static_analyzer import StaticAnalyzer
from c2_detection.c2_detector import (
    build_feature_vector, FEATURE_PERMISSIONS, FEATURE_APIS, FEATURE_NAMES
)

# ─── Config ───────────────────────────────────────────────────────────────────

MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
ANDROZOO_URL       = "https://androzoo.uni.lu/api/download"
ANDROZOO_KEY       = os.getenv("ANDROZOO_KEY", "")

SAMPLES_DIR  = Path("training_samples")
MALWARE_DIR  = SAMPLES_DIR / "malware"
BENIGN_DIR   = SAMPLES_DIR / "benign"
FEATURES_DIR = SAMPLES_DIR / "features"
MODEL_PATH   = Path("c2_detection/droidscan_rf_model.joblib")
REPORT_PATH  = Path("c2_detection/training_report.json")

MALWARE_TAGS = ["SpyNote", "FluBot", "Cerberus", "BankBot", "Joker", "Hiddad", "AndroRAT"]

BENIGN_HASHES: list = [
    # Add real SHA256s from AndroZoo CSV after getting free API key
    # https://androzoo.uni.lu
]


# ─── Downloader ───────────────────────────────────────────────────────────────

class SampleDownloader:

    def __init__(self):
        MALWARE_DIR.mkdir(parents=True, exist_ok=True)
        BENIGN_DIR.mkdir(parents=True, exist_ok=True)
        FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    def download_malware(self, tag: str, limit: int = 50) -> list:
        print(f"[*] Downloading up to {limit} '{tag}' samples from MalwareBazaar...")
        paths = []
        try:
            resp = requests.post(
                MALWARE_BAZAAR_URL,
                data={"query": "get_taginfo", "tag": tag, "limit": limit},
                timeout=30,
            )
            data = resp.json()
            if data.get("query_status") != "ok":
                print(f"[!] No results for tag: {tag}")
                return paths

            for sample in data.get("data", []):
                if sample.get("file_type") != "apk":
                    continue
                sha256   = sample["sha256_hash"]
                out_path = MALWARE_DIR / f"{sha256}.apk"
                if out_path.exists():
                    paths.append(out_path)
                    continue

                dl_resp  = requests.post(
                    MALWARE_BAZAAR_URL,
                    data={"query": "get_file", "sha256_hash": sha256},
                    timeout=60, stream=True,
                )
                zip_path = MALWARE_DIR / f"{sha256}.zip"
                with open(zip_path, "wb") as f:
                    for chunk in dl_resp.iter_content(8192):
                        f.write(chunk)
                try:
                    with zipfile.ZipFile(zip_path, "r") as zf:
                        zf.extractall(MALWARE_DIR, pwd=b"infected")
                    for extracted in MALWARE_DIR.glob("*.apk"):
                        if extracted.name != out_path.name:
                            extracted.rename(out_path)
                            break
                    zip_path.unlink()
                    paths.append(out_path)
                    print(f"  [+] Downloaded: {sha256[:16]}... ({tag})")
                except Exception as e:
                    print(f"  [!] Extract failed: {e}")
                    zip_path.unlink(missing_ok=True)
                time.sleep(0.3)

        except Exception as e:
            print(f"[!] MalwareBazaar error: {e}")
        return paths

    def download_benign(self, hashes: list) -> list:
        if not ANDROZOO_KEY or not hashes:
            print("[!] No ANDROZOO_KEY or no hashes — using synthetic benign samples")
            return []

        print(f"[*] Downloading {len(hashes)} benign APKs from AndroZoo...")
        paths = []
        for sha256 in hashes:
            out_path = BENIGN_DIR / f"{sha256}.apk"
            if out_path.exists():
                paths.append(out_path)
                continue
            try:
                resp = requests.get(
                    ANDROZOO_URL,
                    params={"apikey": ANDROZOO_KEY, "sha256": sha256},
                    timeout=60, stream=True,
                )
                with open(out_path, "wb") as f:
                    for chunk in resp.iter_content(8192):
                        f.write(chunk)
                paths.append(out_path)
                print(f"  [+] Downloaded benign: {sha256[:16]}...")
                time.sleep(0.5)
            except Exception as e:
                print(f"  [!] AndroZoo error for {sha256[:16]}: {e}")
        return paths


# ─── Feature extractor ────────────────────────────────────────────────────────

class FeatureExtractor:

    def extract(self, apk_path: Path, label: int) -> dict:
        cache_path = FEATURES_DIR / f"{apk_path.stem}.json"
        if cache_path.exists():
            with open(cache_path) as f:
                return json.load(f)
        try:
            analyzer = StaticAnalyzer(str(apk_path))
            static   = analyzer.run()
            features = build_feature_vector(static).tolist()
            result   = {
                "apk":      apk_path.name,
                "label":    label,
                "features": features,
                "sha256":   static["meta"].get("sha256", ""),
                "package":  static["meta"].get("package", ""),
            }
            with open(cache_path, "w") as f:
                json.dump(result, f)
            return result
        except Exception as e:
            print(f"  [!] Feature extraction failed for {apk_path.name}: {e}")
            return None

    def build_synthetic_benign(self, count: int) -> list:
        """
        Realistic synthetic benign feature vectors when real APKs unavailable.
        Benign apps use few dangerous permissions, no suspicious APIs, no IOCs.
        """
        print(f"[*] Generating {count} synthetic benign feature vectors...")
        np.random.seed(42)
        synthetic = []
        n_perms = len(FEATURE_PERMISSIONS)
        n_apis  = len(FEATURE_APIS)

        for i in range(count):
            # 0–3 permissions, avoid SMS/call/admin ones (indices 0-5, 12-13)
            perm_vec = [0] * n_perms
            n = np.random.randint(0, 4)
            safe_indices = list(range(4, 12))  # location, audio, camera, etc.
            chosen = np.random.choice(safe_indices,
                                      min(n, len(safe_indices)), replace=False)
            for idx in chosen:
                perm_vec[idx] = 1

            # APIs: only http/crypto occasionally
            api_vec = [0] * n_apis
            for idx in [8, 9]:   # HttpURLConnection, javax.crypto
                api_vec[idx] = np.random.randint(0, 2)

            # Low IOC counts
            ioc_vec  = [np.random.randint(0, 2), np.random.randint(0, 3), 0]
            yara_vec = [0, 0]

            features = perm_vec + api_vec + ioc_vec + yara_vec
            assert len(features) == 30, f"Synthetic feature length: {len(features)}"
            synthetic.append({
                "apk":      f"synthetic_benign_{i}",
                "label":    0,
                "features": features,
            })

        return synthetic


# ─── Trainer ──────────────────────────────────────────────────────────────────

class ModelTrainer:

    def __init__(self):
        self.model = None

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        print(f"[*] Training on {len(X)} samples "
              f"({int(y.sum())} malware, {int(len(y)-y.sum())} benign)...")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        rf = RandomForestClassifier(
            n_estimators=200, max_depth=12,
            min_samples_leaf=2, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )

        cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_auc = cross_val_score(rf, X_train, y_train, cv=cv, scoring="roc_auc")
        print(f"[*] CV ROC-AUC: {cv_auc.mean():.3f} +/- {cv_auc.std():.3f}")

        rf.fit(X_train, y_train)
        self.model = rf

        y_prob = rf.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        report = classification_report(y_test, y_pred,
                                       target_names=["Benign", "Malicious"],
                                       output_dict=True)
        auc = roc_auc_score(y_test, y_prob)
        cm  = confusion_matrix(y_test, y_pred)

        importances = sorted(
            zip(FEATURE_NAMES, rf.feature_importances_),
            key=lambda x: x[1], reverse=True,
        )

        metrics = {
            "roc_auc":           round(auc, 4),
            "cv_auc_mean":       round(cv_auc.mean(), 4),
            "cv_auc_std":        round(cv_auc.std(), 4),
            "precision_malware": round(report["Malicious"]["precision"], 4),
            "recall_malware":    round(report["Malicious"]["recall"], 4),
            "f1_malware":        round(report["Malicious"]["f1-score"], 4),
            "precision_benign":  round(report["Benign"]["precision"], 4),
            "recall_benign":     round(report["Benign"]["recall"], 4),
            "confusion_matrix":  cm.tolist(),
            "top_features":      [(n, round(float(v), 4)) for n, v in importances[:10]],
            "n_train":           int(len(X_train)),
            "n_test":            int(len(X_test)),
            "trained_at":        datetime.utcnow().isoformat() + "Z",
        }

        sep = "-" * 50
        print(f"\n{sep}")
        print(f"  ROC-AUC:              {metrics['roc_auc']:.4f}")
        print(f"  Precision (malware):  {metrics['precision_malware']:.4f}")
        print(f"  Recall (malware):     {metrics['recall_malware']:.4f}")
        print(f"  F1 (malware):         {metrics['f1_malware']:.4f}")
        print("Confusion matrix:")
        print(f"    TN={cm[0,0]:4d}  FP={cm[0,1]:4d}")
        print(f"    FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
        print("Top 5 features:")
        for name, imp in importances[:5]:
            bar = "#" * int(imp * 50)
            print(f"    {name:<30} {imp:.4f}  {bar}")
        print(f"{sep}\n")
        return metrics

    def save(self, metrics: dict):
        joblib.dump(self.model, MODEL_PATH)
        print(f"[+] Model saved: {MODEL_PATH}")
        with open(REPORT_PATH, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"[+] Training report: {REPORT_PATH}")


# ─── Main pipeline ────────────────────────────────────────────────────────────

def main(n_samples: int = 200):
    print("\n" + "=" * 55)
    print("  DroidScan ML Training Pipeline")
    print("=" * 55 + "\n")

    downloader = SampleDownloader()
    extractor  = FeatureExtractor()
    trainer    = ModelTrainer()
    all_features: list = []

    # Download + extract malware
    malware_paths = []
    per_tag = max(1, n_samples // (2 * len(MALWARE_TAGS)))
    for tag in MALWARE_TAGS:
        malware_paths += downloader.download_malware(tag, limit=per_tag)

    print(f"\n[*] Extracting features from {len(malware_paths)} malware APKs...")
    for path in malware_paths:
        result = extractor.extract(path, label=1)
        if result:
            all_features.append(result)

    n_malware = len(all_features)
    print(f"[+] Malware features: {n_malware}")

    # Download + extract benign
    benign_paths = downloader.download_benign(BENIGN_HASHES)
    if benign_paths:
        print(f"\n[*] Extracting features from {len(benign_paths)} benign APKs...")
        for path in benign_paths:
            result = extractor.extract(path, label=0)
            if result:
                all_features.append(result)
    else:
        synthetic = extractor.build_synthetic_benign(max(n_malware, 50))
        all_features.extend(synthetic)

    n_benign = len(all_features) - n_malware
    print(f"[+] Benign features: {n_benign}")
    print(f"[+] Total dataset:   {len(all_features)} samples\n")

    if len(all_features) < 20:
        print("[!] Too few samples. Download more APKs first.")
        return

    X = np.array([s["features"] for s in all_features])
    y = np.array([s["label"]    for s in all_features])

    metrics = trainer.train(X, y)
    trainer.save(metrics)

    print("\n[+] Training complete! Model ready at:", MODEL_PATH)
    print("[+] Add ANDROZOO_KEY env var for real benign samples\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DroidScan ML training")
    parser.add_argument("--samples", type=int, default=200,
                        help="Target number of training samples (default: 200)")
    parser.add_argument("--output",  type=str, default="c2_detection/",
                        help="Output directory for model and report")
    args = parser.parse_args()
    MODEL_PATH  = Path(args.output) / "droidscan_rf_model.joblib"
    REPORT_PATH = Path(args.output) / "training_report.json"
    main(n_samples=args.samples)
