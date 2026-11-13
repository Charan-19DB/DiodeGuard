"""
Feature Engineering Script
Defines the canonical feature schema for all six detection models.
Run after prepare_datasets.py to generate final feature matrices.
"""

import numpy as np
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------------------------
# Canonical feature columns expected by each model
# ---------------------------------------------------------------------------

DDOS_FEATURES = [
    "packets_per_sec", "bytes_per_sec", "src_ip_entropy",
    "dst_port_entropy", "flow_duration", "packet_size_mean",
    "packet_size_std", "syn_ratio", "udp_ratio", "icmp_ratio",
]

BOTNET_FEATURES = [
    "inter_arrival_mean", "inter_arrival_std", "inter_arrival_cv",
    "flow_duration", "bytes_per_pkt", "dst_port",
    "unique_dst_ports_per_src", "flow_count_per_src_5min",
]

DGA_FEATURES = [
    "domain_length", "digit_ratio", "consonant_ratio", "entropy",
    "n_gram_score", "subdomain_count", "query_type_numeric",
    "ttl_mean", "response_size",
]

ENCRYPTED_MALWARE_FEATURES = [
    "tls_version_numeric", "ja3_known_bad", "cert_validity_days",
    "cert_self_signed", "sni_entropy", "bytes_per_sec",
    "packet_size_mean", "packet_size_std", "session_duration",
    "resumption_flag",
]

RECON_FEATURES = [
    "unique_dst_ports", "unique_dst_ips", "syn_no_ack_ratio",
    "flow_duration", "packets_per_sec", "rst_ratio",
    "scan_rate", "bytes_per_pkt",
]

EXFIL_FEATURES = [
    "upload_bytes", "download_bytes", "upload_download_ratio",
    "session_duration", "bytes_per_sec", "entropy_payload",
    "dns_query_length_mean", "http_post_ratio", "unique_domains",
]


def compute_entropy(series: pd.Series) -> float:
    """Shannon entropy of a numeric series."""
    counts = series.value_counts(normalize=True)
    val = float(-(counts * np.log2(counts.clip(lower=1e-9))).sum())
    return max(0.0, val)


def extract_domain_features(domain: str) -> dict:
    """Lexical features for a single domain string."""
    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    consonants = sum(c in "bcdfghjklmnpqrstvwxyz" for c in domain.lower())
    char_counts = pd.Series(list(domain)).value_counts(normalize=True)
    entropy = float(-(char_counts * np.log2(char_counts + 1e-9)).sum())
    return {
        "domain_length": length,
        "digit_ratio": digits / max(length, 1),
        "consonant_ratio": consonants / max(length, 1),
        "entropy": entropy,
    }


def validate_features(df: pd.DataFrame, required_cols: list[str], model_name: str):
    missing = set(required_cols) - set(df.columns)
    if missing:
        raise ValueError(f"[{model_name}] Missing features: {missing}")
    print(f"[{model_name}] ✅ Feature validation passed — {len(required_cols)} features OK")


if __name__ == "__main__":
    processed_dir = Path("datasets/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)
    print("Feature schema loaded. Run prepare_datasets.py to generate data.")
