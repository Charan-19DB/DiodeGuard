"""
Train All Six DiodeGuard Detection Models
Run after: python scripts/prepare_datasets.py

Outputs: models/saved/<model_name>.joblib + models/saved/<model_name>_hash.txt
"""

import sys
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, roc_auc_score, confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.feature_engineering import (
    DDOS_FEATURES, BOTNET_FEATURES, DGA_FEATURES,
    ENCRYPTED_MALWARE_FEATURES, RECON_FEATURES, EXFIL_FEATURES,
)

PROCESSED_DIR = Path("datasets/processed")
SAVED_DIR = Path("models/saved")
SAVED_DIR.mkdir(parents=True, exist_ok=True)

REPORT = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def save_model(model, name: str):
    path = SAVED_DIR / f"{name}.joblib"
    joblib.dump(model, path)
    digest = sha256_file(path)
    (SAVED_DIR / f"{name}_hash.txt").write_text(digest)
    print(f"  Saved → {path}  [SHA-256: {digest[:16]}...]")
    return path


def evaluate_supervised(model, X_test, y_test, name: str):
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    fp_rate = cm[0, 1] / (cm[0, 0] + cm[0, 1] + 1e-9)
    print(f"\n  Precision={p:.3f}  Recall={r:.3f}  F1={f1:.3f}  AUC={auc:.3f}  FP-rate={fp_rate:.4f}")
    REPORT[name] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
                    "auc": round(auc, 4), "fp_rate": round(fp_rate, 4)}


def load_data(dataset: str, features: list[str]):
    df = pd.read_parquet(PROCESSED_DIR / f"{dataset}_features.parquet")
    X = df[features].fillna(0).astype(float)
    y = df["label"].astype(int)
    return X, y


# ---------------------------------------------------------------------------
# Model 1 — DDoS (Random Forest, supervised)
# ---------------------------------------------------------------------------

def train_ddos():
    print("\n[1/6] Training DDoS — Random Forest")
    X, y = load_data("ddos", DDOS_FEATURES)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, max_depth=12, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    evaluate_supervised(clf, X_test, y_test, "ddos")
    save_model(clf, "ddos")
    return clf


# ---------------------------------------------------------------------------
# Model 2 — Botnet C2 Beaconing (Random Forest on inter-arrival stats)
# ---------------------------------------------------------------------------

def train_botnet():
    print("\n[2/6] Training Botnet C2 — Random Forest + inter-arrival stats")
    X, y = load_data("botnet", BOTNET_FEATURES)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, max_depth=10, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    evaluate_supervised(clf, X_test, y_test, "botnet")
    save_model(clf, "botnet")
    return clf


# ---------------------------------------------------------------------------
# Model 3 — DGA / DNS Tunnelling (Random Forest on lexical features)
# ---------------------------------------------------------------------------

def train_dga():
    print("\n[3/6] Training DGA/DNS — Random Forest (lexical features)")
    X, y = load_data("dga", DGA_FEATURES)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    clf = RandomForestClassifier(n_estimators=300, max_depth=15, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    evaluate_supervised(clf, X_test, y_test, "dga")
    save_model(clf, "dga")
    return clf


# ---------------------------------------------------------------------------
# Model 4 — Encrypted Session Malware (Random Forest + JA3 lookup)
# ---------------------------------------------------------------------------

def train_encrypted_malware():
    print("\n[4/6] Training Encrypted Malware — Random Forest + JA3 features")
    X, y = load_data("encrypted_malware", ENCRYPTED_MALWARE_FEATURES)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, max_depth=12, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    evaluate_supervised(clf, X_test, y_test, "encrypted_malware")
    save_model(clf, "encrypted_malware")
    return clf


# ---------------------------------------------------------------------------
# Model 5 — Reconnaissance / Port Scanning (Isolation Forest, unsupervised)
# ---------------------------------------------------------------------------

def train_recon():
    print("\n[5/6] Training Recon/Port-Scan — Isolation Forest")
    X, y = load_data("recon", RECON_FEATURES)
    # Train on benign-only (unsupervised)
    X_benign = X[y == 0]
    iso = IsolationForest(n_estimators=200, contamination=0.05, n_jobs=-1, random_state=42)
    iso.fit(X_benign)
    # Evaluate on full set: Isolation Forest returns -1 (anomaly) or 1 (normal)
    preds = iso.predict(X)
    y_pred_binary = (preds == -1).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y, y_pred_binary, average="binary")
    print(f"  Precision={p:.3f}  Recall={r:.3f}  F1={f1:.3f}")
    REPORT["recon"] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}
    save_model(iso, "recon")
    return iso


# ---------------------------------------------------------------------------
# Model 6 — Data Exfiltration (Isolation Forest, unsupervised)
# ---------------------------------------------------------------------------

def train_exfil():
    print("\n[6/6] Training Data Exfiltration — Isolation Forest")
    X, y = load_data("exfil", EXFIL_FEATURES)
    X_benign = X[y == 0]
    iso = IsolationForest(n_estimators=200, contamination=0.05, n_jobs=-1, random_state=42)
    iso.fit(X_benign)
    preds = iso.predict(X)
    y_pred_binary = (preds == -1).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y, y_pred_binary, average="binary")
    print(f"  Precision={p:.3f}  Recall={r:.3f}  F1={f1:.3f}")
    REPORT["exfil"] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}
    save_model(iso, "exfil")
    return iso


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("DiodeGuard — Training All 6 Detection Models")
    print("=" * 60)
    train_ddos()
    train_botnet()
    train_dga()
    train_encrypted_malware()
    train_recon()
    train_exfil()
    report_path = SAVED_DIR / "eval_report.json"
    report_path.write_text(json.dumps(REPORT, indent=2))
    print(f"\n✅ All models trained. Evaluation report → {report_path}")
    print("\nModel Summary:")
    for model, metrics in REPORT.items():
        f1 = metrics.get("f1", "N/A")
        print(f"  {model:25s} F1={f1}")


if __name__ == "__main__":
    main()
