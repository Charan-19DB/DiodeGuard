"""Unit tests for ML feature engineering and schemas"""

import pandas as pd
from scripts.feature_engineering import (
    DDOS_FEATURES,
    BOTNET_FEATURES,
    DGA_FEATURES,
    ENCRYPTED_MALWARE_FEATURES,
    RECON_FEATURES,
    EXFIL_FEATURES,
    compute_entropy,
    extract_domain_features,
)


def test_feature_lists_non_empty():
    """All 6 feature specifications should be non-empty lists of strings."""
    for feature_list, name in [
        (DDOS_FEATURES, "DDOS_FEATURES"),
        (BOTNET_FEATURES, "BOTNET_FEATURES"),
        (DGA_FEATURES, "DGA_FEATURES"),
        (ENCRYPTED_MALWARE_FEATURES, "ENCRYPTED_MALWARE_FEATURES"),
        (RECON_FEATURES, "RECON_FEATURES"),
        (EXFIL_FEATURES, "EXFIL_FEATURES"),
    ]:
        assert isinstance(feature_list, list), f"{name} is not a list"
        assert len(feature_list) > 0, f"{name} is empty"
        assert all(isinstance(f, str) for f in feature_list), f"{name} contains non-strings"


def test_compute_entropy():
    """Test Shannon entropy calculation on identical vs varied values."""
    uniform_data = pd.Series([1, 1, 1, 1, 1])
    entropy_uniform = compute_entropy(uniform_data)
    assert entropy_uniform >= 0.0

    varied_data = pd.Series([1, 2, 3, 4, 5, 6, 7, 8])
    entropy_varied = compute_entropy(varied_data)
    assert entropy_varied > entropy_uniform


def test_extract_domain_features():
    """Test domain lexical feature extraction."""
    domain = "x7q9b2z9a1c8.xyz"
    features = extract_domain_features(domain)
    
    assert "domain_length" in features
    assert "digit_ratio" in features
    assert "consonant_ratio" in features
    assert "entropy" in features
    assert features["domain_length"] == len(domain)
    assert 0.0 <= features["digit_ratio"] <= 1.0
    assert 0.0 <= features["consonant_ratio"] <= 1.0
