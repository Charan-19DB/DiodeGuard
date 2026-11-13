"""
Stream Replay — Kafka Producer from PCAP
Reads a PCAP file, extracts basic flow features, and publishes them to Kafka.

Usage:
    python ingest/stream_replay.py --pcap data/demo.pcap --rate 500
"""

import argparse
import json
import os
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


def pcap_to_flows(pcap_path: str) -> list[dict]:
    """Convert PCAP packets to flow-level dicts."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("[StreamReplay] Scapy not available — loading mock flows from .json if present")
        json_path = pcap_path + ".json"
        if Path(json_path).exists():
            with open(json_path) as f:
                return json.load(f)
        print(f"[StreamReplay] No mock flows found at {json_path}. Run generate_traffic.py first.")
        return []

    pkts = rdpcap(pcap_path)
    flows = []
    for pkt in pkts:
        if IP not in pkt:
            continue
        flow = {
            "flow_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER",
            "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            "packet_size_mean": len(pkt),
            "packet_size_std": 0,
            "bytes_per_sec": len(pkt),
            "packets_per_sec": 1,
            "flow_duration": 1.0,
            "syn_ratio": 1.0 if (TCP in pkt and pkt[TCP].flags == "S") else 0.0,
            "udp_ratio": 1.0 if UDP in pkt else 0.0,
            "icmp_ratio": 0.0,
            "src_ip_entropy": 0.5,
            "dst_port_entropy": 0.5,
        }
        flows.append(flow)
    return flows


def main():
    parser = argparse.ArgumentParser(description="DiodeGuard Stream Replay")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--rate", type=int, default=100, help="Flows per second to replay")
    args = parser.parse_args()

    flows = pcap_to_flows(args.pcap)
    if not flows:
        print("[StreamReplay] No flows to replay. Exiting.")
        return

    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        kafka_ok = True
        print(f"[StreamReplay] Kafka connected → {KAFKA_BOOTSTRAP}")
    except Exception as e:
        kafka_ok = False
        print(f"[StreamReplay] Kafka unavailable ({e}) — printing flows to stdout instead")

    delay = 1.0 / args.rate
    print(f"[StreamReplay] Replaying {len(flows)} flows at {args.rate} flows/sec...")

    for i, flow in enumerate(flows):
        if kafka_ok:
            producer.send(KAFKA_TOPIC, value=flow)
        else:
            print(json.dumps(flow))

        time.sleep(delay)
        if (i + 1) % 100 == 0:
            print(f"  Sent {i+1}/{len(flows)} flows")

    if kafka_ok:
        producer.flush()
    print(f"[StreamReplay] ✅ Done. {len(flows)} flows replayed.")


if __name__ == "__main__":
    main()
