"""
Continuous Traffic Producer for DiodeGuard
Generates realistic unidirectional network flows and streams them into Kafka in real time.
"""

import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent.parent))

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "diodeguard-flows")
FLOW_RATE = float(os.getenv("FLOW_RATE", "3.0"))  # flows per second


def _rand_ip(prefix="10.0"):
    return f"{prefix}.{random.randint(0,255)}.{random.randint(1,254)}"


def make_benign_flow():
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": _rand_ip("192.168.1"),
        "dst_ip": _rand_ip("10.0.0"),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 53, 8080]),
        "protocol": random.choice(["TCP", "UDP"]),
        "packets_per_sec": random.uniform(10, 150),
        "bytes_per_sec": random.uniform(500, 45000),
        "syn_ratio": random.uniform(0.01, 0.15),
        "udp_ratio": random.uniform(0.0, 0.20),
        "icmp_ratio": 0.0,
        "src_ip_entropy": random.uniform(0.1, 0.35),
        "dst_port_entropy": random.uniform(0.1, 0.40),
        "inter_arrival_cv": random.uniform(0.8, 1.8),
        "flow_duration": random.uniform(0.5, 30.0),
    }


def make_ddos_flow():
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": _rand_ip("198.51.100"),
        "dst_ip": "10.0.0.5",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": "TCP",
        "packets_per_sec": random.uniform(12000, 32000),
        "bytes_per_sec": random.uniform(5e7, 1.5e8),
        "syn_ratio": random.uniform(0.92, 1.0),
        "udp_ratio": 0.0,
        "icmp_ratio": 0.0,
        "src_ip_entropy": random.uniform(0.85, 0.99),
        "dst_port_entropy": random.uniform(0.0, 0.05),
        "flow_duration": random.uniform(0.05, 1.5),
        "packet_size_mean": random.uniform(40, 70),
        "packet_size_std": random.uniform(0, 5),
    }


def make_botnet_flow():
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.4.12",
        "dst_ip": "203.0.113.88",
        "src_port": random.randint(40000, 60000),
        "dst_port": random.choice([4444, 6667, 1337]),
        "protocol": "TCP",
        "inter_arrival_mean": 60.0 + random.uniform(-0.5, 0.5),
        "inter_arrival_std": random.uniform(0.05, 0.3),
        "inter_arrival_cv": random.uniform(0.001, 0.015),
        "bytes_per_pkt": random.uniform(90, 180),
        "unique_dst_ports_per_src": 1,
        "flow_count_per_src_5min": random.randint(4, 7),
        "flow_duration": 1.2,
        "packets_per_sec": 5,
        "bytes_per_sec": 600,
    }


def make_dga_flow():
    chars = "abcdefghijklmnopqrstuvwxyz"
    domain = "".join(random.choices(chars, k=random.randint(18, 30))) + ".info"
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": _rand_ip("10.0.2"),
        "dst_ip": "8.8.8.8",
        "src_port": random.randint(50000, 65000),
        "dst_port": 53,
        "protocol": "UDP",
        "domain": domain,
        "domain_length": len(domain),
        "entropy": random.uniform(3.8, 4.5),
        "digit_ratio": 0.0,
        "consonant_ratio": random.uniform(0.7, 0.9),
        "packets_per_sec": random.uniform(1, 10),
        "bytes_per_sec": random.uniform(100, 800),
    }


def make_recon_flow():
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(50000, 60000),
        "dst_port": random.randint(1, 1024),
        "protocol": "TCP",
        "unique_dst_ports": random.randint(45, 300),
        "unique_dst_ips": 1,
        "syn_no_ack_ratio": 1.0,
        "scan_rate": random.uniform(60, 200),
        "packets_per_sec": random.uniform(200, 1000),
        "bytes_per_sec": random.uniform(10000, 60000),
    }


def make_exfil_flow():
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.1.200",
        "dst_ip": "203.0.113.250",
        "src_port": random.randint(40000, 55000),
        "dst_port": 8080,
        "protocol": "TCP",
        "upload_bytes": random.uniform(1e7, 8e7),
        "download_bytes": random.uniform(500, 2000),
        "upload_download_ratio": random.uniform(25, 80),
        "bytes_per_sec": random.uniform(6e6, 2e7),
        "packets_per_sec": random.uniform(5000, 15000),
        "flow_duration": random.uniform(5, 20),
    }


def get_random_flow():
    roll = random.random()
    if roll < 0.65:
        return make_benign_flow()
    elif roll < 0.75:
        return make_ddos_flow()
    elif roll < 0.83:
        return make_botnet_flow()
    elif roll < 0.90:
        return make_dga_flow()
    elif roll < 0.95:
        return make_recon_flow()
    else:
        return make_exfil_flow()


def main():
    print(f"[TrafficGenerator] Starting continuous traffic stream...")
    print(f"[TrafficGenerator] Target Kafka: {KAFKA_BOOTSTRAP}, Topic: {KAFKA_TOPIC}, Rate: {FLOW_RATE} flows/s")

    producer = None
    retries = 30
    while retries > 0:
        try:
            from kafka import KafkaProducer
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            print("[TrafficGenerator] ✅ Connected to Kafka broker!")
            break
        except Exception as e:
            print(f"[TrafficGenerator] Waiting for Kafka broker ({e})... {retries} retries remaining")
            time.sleep(3)
            retries -= 1

    delay = 1.0 / max(FLOW_RATE, 0.1)
    count = 0

    while True:
        flow = get_random_flow()
        if producer:
            try:
                producer.send(KAFKA_TOPIC, value=flow)
            except Exception as e:
                print(f"[TrafficGenerator WARN] Send failed: {e}")
        count += 1
        if count % 50 == 0:
            print(f"[TrafficGenerator] Streamed {count} flows into '{KAFKA_TOPIC}'...")
        time.sleep(delay)


if __name__ == "__main__":
    main()
