"""
Detector — Orchestrates all 6 ML models
Loads trained .joblib files (with SHA-256 integrity check),
scores each incoming flow record, and emits alerts.
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.feature_engineering import (
    DDOS_FEATURES, BOTNET_FEATURES, DGA_FEATURES,
    ENCRYPTED_MALWARE_FEATURES, RECON_FEATURES, EXFIL_FEATURES,
)

MODEL_DIR = Path(os.getenv("MODEL_DIR", "models/saved"))
THRESHOLD = float(os.getenv("ALERT_CONFIDENCE_THRESHOLD", "0.75"))

SEVERITY_MAP = {
    (0.75, 0.85): "Medium",
    (0.85, 0.92): "High",
    (0.92, 1.01): "Critical",
}

SUPERVISED_MODELS = {
    "DDoS": ("ddos", DDOS_FEATURES),
    "BotnetC2": ("botnet", BOTNET_FEATURES),
    "DGA": ("dga", DGA_FEATURES),
    "EncryptedMalware": ("encrypted_malware", ENCRYPTED_MALWARE_FEATURES),
}

UNSUPERVISED_MODELS = {
    "Recon": ("recon", RECON_FEATURES),
    "Exfiltration": ("exfil", EXFIL_FEATURES),
}


def _verify_and_load(name: str):
    model_path = MODEL_DIR / f"{name}.joblib"
    hash_path = MODEL_DIR / f"{name}_hash.txt"
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if hash_path.exists():
        expected = hash_path.read_text().strip()
        actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"SHA-256 mismatch for {name}! Model file may be tampered.")
    return joblib.load(model_path)


def get_severity(score: float) -> str:
    if score < 0.75:
        return "Low"
    for (lo, hi), sev in SEVERITY_MAP.items():
        if lo <= score < hi:
            return sev
    return "Critical"


class DiodeGuardDetector:
    def __init__(self):
        print("[Detector] Loading models...")
        self.supervised = {}
        self.unsupervised = {}

        missing_any = False
        for threat, (name, _) in {**SUPERVISED_MODELS, **UNSUPERVISED_MODELS}.items():
            if not (MODEL_DIR / f"{name}.joblib").exists():
                missing_any = True
                break

        if missing_any:
            try:
                print("[Detector] Model artifacts missing on disk. Attempting auto-training...")
                import models.train_all as trainer
                trainer.main()
            except Exception as e:
                print(f"[Detector] Auto-training skipped ({e}). Calibrated heuristic rules active as fallback.")

        for threat, (name, _) in SUPERVISED_MODELS.items():
            try:
                self.supervised[threat] = _verify_and_load(name)
                print(f"  ✅ {threat} ({name})")
            except Exception as e:
                print(f"  ⚠️  {threat} model not loaded ({e}) — using heuristic fallback")
                self.supervised[threat] = None

        for threat, (name, _) in UNSUPERVISED_MODELS.items():
            try:
                self.unsupervised[threat] = _verify_and_load(name)
                print(f"  ✅ {threat} ({name})")
            except Exception as e:
                print(f"  ⚠️  {threat} model not loaded ({e}) — using heuristic fallback")
                self.unsupervised[threat] = None

    def _heuristic_score(self, flow: dict, threat: str) -> float:
        """Calibrated fallback scoring when scikit-learn binary artifacts are absent."""
        pps = float(flow.get("packets_per_sec", 0))
        bps = float(flow.get("bytes_per_sec", 0))
        syn = float(flow.get("syn_ratio", 0))
        entropy = float(flow.get("src_ip_entropy", 0))
        cv = float(flow.get("inter_arrival_cv", 1.0))
        dst_port = int(flow.get("dst_port", 0))
        unique_ports = int(flow.get("unique_dst_ports", 0))

        if threat == "DDoS" and (pps > 4000 or syn > 0.75 or entropy > 0.70):
            return 0.94 if pps > 10000 else 0.86
        if threat == "BotnetC2" and (cv < 0.05 or dst_port in (4444, 6667, 1337, 9001)):
            return 0.91 if cv < 0.02 else 0.84
        if threat == "DGA" and (flow.get("domain_length", 0) > 16 or flow.get("entropy", 0) > 3.6):
            return 0.88
        if threat == "EncryptedMalware" and (flow.get("ja3_known_bad", False) or flow.get("cert_validity_days", 365) < 3):
            return 0.89
        if threat == "Recon" and (unique_ports > 30 or flow.get("scan_rate", 0) > 50):
            return 0.85
        if threat == "Exfiltration" and (bps > 5e6 or flow.get("upload_download_ratio", 0) > 20):
            return 0.83
        return 0.0

    def score_flow(self, flow: dict) -> list[dict]:
        """
        Score a single flow record against all 6 models.
        Returns a list of alert dicts (empty if no threat detected above threshold).
        """
        alerts = []

        # --- Supervised models (return probability) ---
        for threat, (_, features) in SUPERVISED_MODELS.items():
            model = self.supervised.get(threat)
            if model is None:
                h_score = self._heuristic_score(flow, threat)
                if h_score >= THRESHOLD:
                    alerts.append(self._make_alert(flow, threat, h_score, features))
                continue
            try:
                X = self._extract(flow, features)
                prob = model.predict_proba(X)[0][1]
                if prob >= THRESHOLD:
                    alerts.append(self._make_alert(flow, threat, prob, features))
            except Exception as e:
                print(f"  [WARN] {threat} scoring failed: {e}")

        # --- Unsupervised models (Isolation Forest: -1 = anomaly) ---
        for threat, (_, features) in UNSUPERVISED_MODELS.items():
            model = self.unsupervised.get(threat)
            if model is None:
                h_score = self._heuristic_score(flow, threat)
                if h_score >= THRESHOLD:
                    alerts.append(self._make_alert(flow, threat, h_score, features))
                continue
            try:
                X = self._extract(flow, features)
                score = -model.score_samples(X)[0]  # higher = more anomalous
                confidence = float(np.clip((score + 0.5) / 1.0, 0, 1))
                if confidence >= THRESHOLD:
                    alerts.append(self._make_alert(flow, threat, confidence, features))
            except Exception as e:
                print(f"  [WARN] {threat} scoring failed: {e}")

        return alerts

    def _extract(self, flow: dict, features: list[str]) -> pd.DataFrame:
        row = {f: float(flow.get(f, 0)) for f in features}
        return pd.DataFrame([row])

    def _make_alert(self, flow: dict, threat_class: str, confidence: float, features: list[str]) -> dict:
        evidence = {f: flow.get(f, 0) for f in features[:5]}  # top 5 features as evidence
        return {
            "alert_id": str(uuid.uuid4()),
            "flow_id": flow.get("flow_id", str(uuid.uuid4())),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_class": threat_class,
            "confidence_score": round(float(confidence), 4),
            "severity": get_severity(confidence),
            "evidence": evidence,
            "src_ip": flow.get("src_ip", "0.0.0.0"),
            "dst_ip": flow.get("dst_ip", "0.0.0.0"),
            "src_port": int(flow.get("src_port", 0)),
            "dst_port": int(flow.get("dst_port", 0)),
            "protocol": flow.get("protocol", "TCP"),
        }


if __name__ == "__main__":
    # Quick smoke test with synthetic flows
    detector = DiodeGuardDetector()
    test_flow = {
        "flow_id": "test-001",
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "packets_per_sec": 18000,
        "bytes_per_sec": 9e7,
        "src_ip_entropy": 0.95,
        "dst_port_entropy": 0.05,
        "flow_duration": 0.8,
        "packet_size_mean": 60,
        "packet_size_std": 5,
        "syn_ratio": 0.95,
        "udp_ratio": 0.0,
        "icmp_ratio": 0.0,
    }
    alerts = detector.score_flow(test_flow)
    print(f"\nTest flow generated {len(alerts)} alert(s):")
    for a in alerts:
        print(json.dumps(a, indent=2))
