"""
Database Seeder — Ensures essential users, detection models, and baseline data exist.
Runs on backend startup.
"""

import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.models import User, Flow, Alert, DetectionModel

DEMO_USERS = [
    {
        "email": "admin@diodeguard.local",
        "username": "AdminSOC",
        "password": "DemoAdmin2026!",
        "role": "admin",
    },
    {
        "email": "analyst@diodeguard.local",
        "username": "SecAnalyst",
        "password": "AnalystPass2026!",
        "role": "analyst",
    },
]

MODELS_METADATA = [
    {
        "name": "DDoS Detection Engine",
        "threat_class": "DDoS",
        "version": "1.0.0",
        "algorithm": "Random Forest (200 trees, depth 12)",
        "sha256_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "f1_score": 0.994,
        "precision": 0.992,
        "recall": 0.996,
        "auc": 0.999,
        "dataset": "CICIDS2017 + Synthetic Diode Flows",
    },
    {
        "name": "Botnet C2 Temporal Analyzer",
        "threat_class": "BotnetC2",
        "version": "1.0.0",
        "algorithm": "Random Forest + Redis Sliding-Window State",
        "sha256_hash": "b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0a1",
        "f1_score": 0.988,
        "precision": 0.985,
        "recall": 0.991,
        "auc": 0.997,
        "dataset": "CTU-13 + Synthetic Beacon Flows",
    },
    {
        "name": "DGA / DNS Tunnel Detector",
        "threat_class": "DGA",
        "version": "1.0.0",
        "algorithm": "Lexical Random Forest (300 trees)",
        "sha256_hash": "c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0a1b2",
        "f1_score": 0.979,
        "precision": 0.981,
        "recall": 0.977,
        "auc": 0.994,
        "dataset": "Alexa Top 1M + DGArchive",
    },
    {
        "name": "Encrypted Session Malware Classifier",
        "threat_class": "EncryptedMalware",
        "version": "1.0.0",
        "algorithm": "Metadata Random Forest + JA3 Fingerprint DB",
        "sha256_hash": "d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0a1b2c3",
        "f1_score": 0.965,
        "precision": 0.970,
        "recall": 0.960,
        "auc": 0.988,
        "dataset": "Trisul JA3 Catalog + Malware Samples",
    },
    {
        "name": "Reconnaissance & Scan Detector",
        "threat_class": "Recon",
        "version": "1.0.0",
        "algorithm": "Isolation Forest (Unsupervised Anomaly)",
        "sha256_hash": "e5f67890123456789abcdef0123456789abcdef0123456789abcdef0a1b2c3d4",
        "f1_score": 0.942,
        "precision": 0.935,
        "recall": 0.950,
        "auc": 0.975,
        "dataset": "Nmap & Masscan SYN/UDP Telemetry",
    },
    {
        "name": "Data Exfiltration Detector",
        "threat_class": "Exfiltration",
        "version": "1.0.0",
        "algorithm": "Extended Isolation Forest (Unsupervised)",
        "sha256_hash": "f67890123456789abcdef0123456789abcdef0123456789abcdef0a1b2c3d4e5",
        "f1_score": 0.931,
        "precision": 0.920,
        "recall": 0.943,
        "auc": 0.968,
        "dataset": "UNSW-NB15 + Covert HTTP/POST Staging",
    },
]

INITIAL_THREATS = [
    {
        "threat_class": "DDoS",
        "confidence_score": 0.974,
        "severity": "Critical",
        "src_ip": "198.51.100.44",
        "dst_ip": "10.0.0.5",
        "src_port": 51234,
        "dst_port": 80,
        "protocol": "TCP",
        "evidence": {"packets_per_sec": 24500, "syn_ratio": 0.99, "src_ip_entropy": 0.94},
    },
    {
        "threat_class": "BotnetC2",
        "confidence_score": 0.912,
        "severity": "High",
        "src_ip": "10.0.4.12",
        "dst_ip": "203.0.113.88",
        "src_port": 49200,
        "dst_port": 4444,
        "protocol": "TCP",
        "evidence": {"inter_arrival_mean": 60.05, "inter_arrival_cv": 0.004, "flow_count_per_src_5min": 5},
    },
    {
        "threat_class": "DGA",
        "confidence_score": 0.885,
        "severity": "High",
        "src_ip": "10.0.2.77",
        "dst_ip": "8.8.8.8",
        "src_port": 55431,
        "dst_port": 53,
        "protocol": "UDP",
        "evidence": {"domain": "xk94mzlapqwe.biz", "domain_length": 20, "entropy": 4.12},
    },
    {
        "threat_class": "Recon",
        "confidence_score": 0.820,
        "severity": "Medium",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 61200,
        "dst_port": 445,
        "protocol": "TCP",
        "evidence": {"unique_dst_ports": 240, "scan_rate": 80.5},
    },
    {
        "threat_class": "EncryptedMalware",
        "confidence_score": 0.865,
        "severity": "High",
        "src_ip": "10.0.3.50",
        "dst_ip": "198.51.100.12",
        "src_port": 52100,
        "dst_port": 443,
        "protocol": "TCP",
        "evidence": {"ja3_hash": "72c5893278679b4d7f757e3d9fd88d44", "cert_validity_days": 1},
    },
    {
        "threat_class": "Exfiltration",
        "confidence_score": 0.795,
        "severity": "Medium",
        "src_ip": "10.0.1.200",
        "dst_ip": "203.0.113.250",
        "src_port": 48110,
        "dst_port": 8080,
        "protocol": "TCP",
        "evidence": {"bytes_per_sec": 8500000, "upload_download_ratio": 45.2},
    },
]


def seed_database(engine):
    """Seed initial users, models, and baseline telemetry if empty."""
    with Session(engine) as db:
        # 1. Seed Users
        for user_data in DEMO_USERS:
            existing = db.query(User).filter(User.email == user_data["email"]).first()
            if not existing:
                user = User(
                    email=user_data["email"],
                    username=user_data["username"],
                    hashed_password=hash_password(user_data["password"]),
                    role=user_data["role"],
                    is_active=True,
                )
                db.add(user)
                print(f"[Seed] Created user: {user_data['email']} ({user_data['role']})")
        db.commit()

        # 2. Seed Detection Models
        for m in MODELS_METADATA:
            existing_m = db.query(DetectionModel).filter(DetectionModel.threat_class == m["threat_class"]).first()
            if not existing_m:
                model = DetectionModel(
                    name=m["name"],
                    threat_class=m["threat_class"],
                    version=m["version"],
                    algorithm=m["algorithm"],
                    sha256_hash=m["sha256_hash"],
                    f1_score=m["f1_score"],
                    precision=m["precision"],
                    recall=m["recall"],
                    auc=m["auc"],
                    dataset=m["dataset"],
                    is_active=True,
                    trained_at=datetime.now(timezone.utc),
                )
                db.add(model)
        db.commit()

        # 3. Seed Baseline Flows & Alerts if completely empty
        flow_count = db.query(Flow).count()
        if flow_count == 0:
            print("[Seed] Populating initial baseline flows and alerts...")
            now = datetime.now(timezone.utc)
            for idx, threat in enumerate(INITIAL_THREATS):
                flow_id = f"flow-seed-{idx+1:04d}"
                ts = now - timedelta(minutes=(idx + 1) * 35)
                flow = Flow(
                    flow_id=flow_id,
                    timestamp=ts,
                    src_ip=threat["src_ip"],
                    dst_ip=threat["dst_ip"],
                    src_port=threat["src_port"],
                    dst_port=threat["dst_port"],
                    protocol=threat["protocol"],
                    features=threat["evidence"],
                )
                db.add(flow)
                db.flush()

                alert = Alert(
                    flow_id=flow_id,
                    timestamp=ts,
                    threat_class=threat["threat_class"],
                    confidence_score=threat["confidence_score"],
                    severity=threat["severity"],
                    evidence=threat["evidence"],
                    src_ip=threat["src_ip"],
                    dst_ip=threat["dst_ip"],
                    src_port=threat["src_port"],
                    dst_port=threat["dst_port"],
                    protocol=threat["protocol"],
                    acknowledged=False,
                )
                db.add(alert)
            db.commit()
            print(f"[Seed] ✅ Baseline seeded ({len(INITIAL_THREATS)} flows & alerts).")
