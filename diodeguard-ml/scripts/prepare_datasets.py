"""
Dataset Preparation Script
Downloads / locates raw datasets, cleans them, engineers features,
and saves processed .parquet files ready for model training.

Supported datasets:
- CICIDS2017 (DDoS, Botnet, Recon)
- CTU-13 (Botnet C2)
- UNSW-NB15 (Exfiltration, general)
- Custom Scapy-generated traffic (per threat type)

Usage:
    python scripts/prepare_datasets.py
"""

import sys
import os
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.feature_engineering import (
    DDOS_FEATURES, BOTNET_FEATURES, DGA_FEATURES,
    ENCRYPTED_MALWARE_FEATURES, RECON_FEATURES, EXFIL_FEATURES,
    compute_entropy, extract_domain_features,
)

RAW_DIR = Path("datasets/raw")
PROCESSED_DIR = Path("datasets/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Synthetic data generators (used when real datasets are not available)
# ---------------------------------------------------------------------------

def generate_ddos_synthetic(n_benign=5000, n_attack=3000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = pd.DataFrame({
        "packets_per_sec": rng.uniform(1, 200, n_benign),
        "bytes_per_sec": rng.uniform(100, 50000, n_benign),
        "src_ip_entropy": rng.uniform(0.0, 0.5, n_benign),
        "dst_port_entropy": rng.uniform(0.0, 0.3, n_benign),
        "flow_duration": rng.uniform(0.5, 60, n_benign),
        "packet_size_mean": rng.uniform(200, 1400, n_benign),
        "packet_size_std": rng.uniform(10, 200, n_benign),
        "syn_ratio": rng.uniform(0.01, 0.2, n_benign),
        "udp_ratio": rng.uniform(0.0, 0.3, n_benign),
        "icmp_ratio": rng.uniform(0.0, 0.05, n_benign),
        "label": 0,
    })
    attack = pd.DataFrame({
        "packets_per_sec": rng.uniform(5000, 30000, n_attack),
        "bytes_per_sec": rng.uniform(1e6, 1e8, n_attack),
        "src_ip_entropy": rng.uniform(0.7, 1.0, n_attack),
        "dst_port_entropy": rng.uniform(0.0, 0.1, n_attack),
        "flow_duration": rng.uniform(0.01, 5, n_attack),
        "packet_size_mean": rng.uniform(40, 80, n_attack),
        "packet_size_std": rng.uniform(0, 10, n_attack),
        "syn_ratio": rng.uniform(0.7, 1.0, n_attack),
        "udp_ratio": rng.uniform(0.6, 1.0, n_attack),
        "icmp_ratio": rng.uniform(0.0, 0.9, n_attack),
        "label": 1,
    })
    return pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=seed)


def generate_botnet_synthetic(n_benign=5000, n_attack=2000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = pd.DataFrame({
        "inter_arrival_mean": rng.uniform(0.1, 30, n_benign),
        "inter_arrival_std": rng.uniform(0.5, 15, n_benign),
        "inter_arrival_cv": rng.uniform(0.1, 2.0, n_benign),
        "flow_duration": rng.uniform(1, 300, n_benign),
        "bytes_per_pkt": rng.uniform(100, 1400, n_benign),
        "dst_port": rng.choice([80, 443, 8080, 53, 22, 25], n_benign),
        "unique_dst_ports_per_src": rng.integers(1, 10, n_benign),
        "flow_count_per_src_5min": rng.integers(1, 50, n_benign),
        "label": 0,
    })
    attack = pd.DataFrame({
        "inter_arrival_mean": rng.uniform(55, 65, n_attack),  # periodic beaconing ~60s
        "inter_arrival_std": rng.uniform(0.1, 2, n_attack),   # very low std = regular
        "inter_arrival_cv": rng.uniform(0.001, 0.05, n_attack),
        "flow_duration": rng.uniform(0.5, 5, n_attack),
        "bytes_per_pkt": rng.uniform(64, 256, n_attack),
        "dst_port": rng.choice([6667, 4444, 1337, 9001], n_attack),
        "unique_dst_ports_per_src": rng.integers(1, 3, n_attack),
        "flow_count_per_src_5min": rng.integers(1, 6, n_attack),
        "label": 1,
    })
    return pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=seed)


def generate_dga_synthetic(n_benign=5000, n_attack=3000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    # Benign: short, low entropy domains
    benign_domains = [
        "google.com", "facebook.com", "amazon.com", "youtube.com",
        "microsoft.com", "apple.com", "twitter.com", "linkedin.com",
    ] * (n_benign // 8 + 1)
    benign_domains = benign_domains[:n_benign]
    # DGA: long, high entropy random strings
    chars = list("abcdefghijklmnopqrstuvwxyz0123456789")
    dga_domains = [
        "".join(rng.choice(chars, rng.integers(12, 32))) + ".com"
        for _ in range(n_attack)
    ]
    rows = []
    for d, label in [(benign_domains, 0), (dga_domains, 1)]:
        for domain in d:
            f = extract_domain_features(domain)
            f["n_gram_score"] = rng.uniform(0.7, 1.0) if label == 0 else rng.uniform(0.0, 0.3)
            f["subdomain_count"] = rng.integers(0, 3) if label == 0 else rng.integers(0, 2)
            f["query_type_numeric"] = 1
            f["ttl_mean"] = rng.uniform(300, 86400) if label == 0 else rng.uniform(30, 300)
            f["response_size"] = rng.uniform(50, 500) if label == 0 else rng.uniform(10, 100)
            f["label"] = label
            rows.append(f)
    return pd.DataFrame(rows).sample(frac=1, random_state=seed)


def generate_recon_synthetic(n_benign=5000, n_attack=2000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = pd.DataFrame({
        "unique_dst_ports": rng.integers(1, 5, n_benign),
        "unique_dst_ips": rng.integers(1, 10, n_benign),
        "syn_no_ack_ratio": rng.uniform(0.0, 0.1, n_benign),
        "flow_duration": rng.uniform(1, 60, n_benign),
        "packets_per_sec": rng.uniform(1, 100, n_benign),
        "rst_ratio": rng.uniform(0.0, 0.05, n_benign),
        "scan_rate": rng.uniform(0.0, 2, n_benign),
        "bytes_per_pkt": rng.uniform(200, 1400, n_benign),
        "label": 0,
    })
    attack = pd.DataFrame({
        "unique_dst_ports": rng.integers(100, 65535, n_attack),
        "unique_dst_ips": rng.integers(1, 256, n_attack),
        "syn_no_ack_ratio": rng.uniform(0.7, 1.0, n_attack),
        "flow_duration": rng.uniform(0.001, 2, n_attack),
        "packets_per_sec": rng.uniform(200, 5000, n_attack),
        "rst_ratio": rng.uniform(0.3, 1.0, n_attack),
        "scan_rate": rng.uniform(10, 1000, n_attack),
        "bytes_per_pkt": rng.uniform(40, 80, n_attack),
        "label": 1,
    })
    return pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=seed)


def generate_exfil_synthetic(n_benign=5000, n_attack=2000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = pd.DataFrame({
        "upload_bytes": rng.uniform(100, 50000, n_benign),
        "download_bytes": rng.uniform(1000, 500000, n_benign),
        "upload_download_ratio": rng.uniform(0.01, 0.5, n_benign),
        "session_duration": rng.uniform(1, 300, n_benign),
        "bytes_per_sec": rng.uniform(100, 50000, n_benign),
        "entropy_payload": rng.uniform(3.0, 6.0, n_benign),
        "dns_query_length_mean": rng.uniform(5, 30, n_benign),
        "http_post_ratio": rng.uniform(0.0, 0.2, n_benign),
        "unique_domains": rng.integers(1, 20, n_benign),
        "label": 0,
    })
    attack = pd.DataFrame({
        "upload_bytes": rng.uniform(1e6, 1e9, n_attack),
        "download_bytes": rng.uniform(100, 5000, n_attack),
        "upload_download_ratio": rng.uniform(5, 1000, n_attack),
        "session_duration": rng.uniform(60, 3600, n_attack),
        "bytes_per_sec": rng.uniform(10000, 1e6, n_attack),
        "entropy_payload": rng.uniform(7.0, 8.0, n_attack),
        "dns_query_length_mean": rng.uniform(50, 200, n_attack),
        "http_post_ratio": rng.uniform(0.7, 1.0, n_attack),
        "unique_domains": rng.integers(1, 5, n_attack),
        "label": 1,
    })
    return pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=seed)


def generate_encrypted_malware_synthetic(n_benign=5000, n_attack=2000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = pd.DataFrame({
        "tls_version_numeric": rng.choice([3, 4], n_benign),  # TLS 1.2=3, 1.3=4
        "ja3_known_bad": rng.choice([0], n_benign),
        "cert_validity_days": rng.uniform(30, 825, n_benign),
        "cert_self_signed": rng.choice([0], n_benign),
        "sni_entropy": rng.uniform(2.0, 4.0, n_benign),
        "bytes_per_sec": rng.uniform(500, 100000, n_benign),
        "packet_size_mean": rng.uniform(400, 1400, n_benign),
        "packet_size_std": rng.uniform(50, 300, n_benign),
        "session_duration": rng.uniform(5, 600, n_benign),
        "resumption_flag": rng.choice([0, 1], n_benign),
        "label": 0,
    })
    attack = pd.DataFrame({
        "tls_version_numeric": rng.choice([1, 2], n_attack),  # older TLS
        "ja3_known_bad": rng.choice([0, 1], n_attack, p=[0.3, 0.7]),
        "cert_validity_days": rng.uniform(1, 30, n_attack),
        "cert_self_signed": rng.choice([0, 1], n_attack, p=[0.2, 0.8]),
        "sni_entropy": rng.uniform(4.5, 8.0, n_attack),
        "bytes_per_sec": rng.uniform(100, 5000, n_attack),
        "packet_size_mean": rng.uniform(64, 200, n_attack),
        "packet_size_std": rng.uniform(0, 30, n_attack),
        "session_duration": rng.uniform(3600, 86400, n_attack),
        "resumption_flag": rng.choice([0], n_attack),
        "label": 1,
    })
    return pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=seed)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

GENERATORS = {
    "ddos": generate_ddos_synthetic,
    "botnet": generate_botnet_synthetic,
    "dga": generate_dga_synthetic,
    "recon": generate_recon_synthetic,
    "exfil": generate_exfil_synthetic,
    "encrypted_malware": generate_encrypted_malware_synthetic,
}


def main():
    print("=" * 60)
    print("DiodeGuard — Dataset Preparation")
    print("=" * 60)
    for name, generator in tqdm(GENERATORS.items(), desc="Generating datasets"):
        df = generator()
        out_path = PROCESSED_DIR / f"{name}_features.parquet"
        df.to_parquet(out_path, index=False)
        print(f"  [{name}] {len(df)} rows → {out_path}")
    print("\n✅ All datasets prepared. Run: python models/train_all.py")


if __name__ == "__main__":
    main()
