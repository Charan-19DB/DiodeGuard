"""
Traffic Simulator — Scapy-based PCAP Generator
Generates synthetic PCAP files containing benign + attack traffic
for all six threat categories.

Usage:
    python traffic_sim/generate_traffic.py --output data/demo.pcap --count 1000
"""

import argparse
import os
import random
import sys
from pathlib import Path

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, Ether,
        wrpcap, RandShort, RandMAC,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Generating mock flow records instead.")


def _rand_ip(prefix="10.0"):
    return f"{prefix}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_ddos_packets(count=200):
    pkts = []
    if not SCAPY_AVAILABLE:
        return pkts
    dst = "192.168.1.100"
    for _ in range(count):
        pkt = (IP(src=_rand_ip(), dst=dst) /
               TCP(sport=RandShort(), dport=80, flags="S") /
               b"X" * 60)
        pkts.append(pkt)
    return pkts


def generate_botnet_packets(count=50):
    pkts = []
    if not SCAPY_AVAILABLE:
        return pkts
    src = _rand_ip("172.16")
    c2 = "203.0.113.5"
    for _ in range(count):
        pkt = (IP(src=src, dst=c2) /
               TCP(sport=RandShort(), dport=4444, flags="PA") /
               b"\x00" * 128)
        pkts.append(pkt)
    return pkts


def generate_dns_dga_packets(count=100):
    pkts = []
    if not SCAPY_AVAILABLE:
        return pkts
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(count):
        domain = "".join(random.choices(chars, k=random.randint(16, 28))) + ".com"
        pkt = (IP(src=_rand_ip(), dst="8.8.8.8") /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=domain)))
        pkts.append(pkt)
    return pkts


def generate_recon_packets(count=300):
    pkts = []
    if not SCAPY_AVAILABLE:
        return pkts
    src = _rand_ip("10.1")
    target = _rand_ip("10.2")
    for port in random.sample(range(1, 65536), min(count, 1000)):
        pkt = (IP(src=src, dst=target) /
               TCP(sport=RandShort(), dport=port, flags="S"))
        pkts.append(pkt)
    return pkts


def generate_benign_packets(count=500):
    pkts = []
    if not SCAPY_AVAILABLE:
        return pkts
    for _ in range(count):
        pkt = (IP(src=_rand_ip("192.168.0"), dst=_rand_ip("10.0")) /
               TCP(sport=RandShort(), dport=random.choice([80, 443, 22, 25])) /
               b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        pkts.append(pkt)
    return pkts


def main():
    parser = argparse.ArgumentParser(description="DiodeGuard Traffic Simulator")
    parser.add_argument("--output", default="data/demo.pcap", help="Output PCAP file")
    parser.add_argument("--count", type=int, default=1000, help="Total approximate packet count")
    args = parser.parse_args()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    if not SCAPY_AVAILABLE:
        print(f"[Simulator] Scapy unavailable — generating mock flow JSON to {args.output}.json")
        import json, uuid
        from datetime import datetime, timezone
        flows = []
        for i in range(args.count):
            flows.append({
                "flow_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": _rand_ip(),
                "dst_ip": _rand_ip("10.0"),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 53, 4444]),
                "protocol": random.choice(["TCP", "UDP"]),
                "packets_per_sec": random.uniform(1, 20000),
                "bytes_per_sec": random.uniform(100, 1e8),
            })
        with open(args.output + ".json", "w") as f:
            json.dump(flows, f, indent=2)
        print(f"[Simulator] ✅ {len(flows)} mock flows → {args.output}.json")
        return

    print("[Simulator] Generating traffic...")
    all_pkts = []
    all_pkts += generate_benign_packets(args.count // 2)
    all_pkts += generate_ddos_packets(args.count // 8)
    all_pkts += generate_botnet_packets(args.count // 8)
    all_pkts += generate_dns_dga_packets(args.count // 8)
    all_pkts += generate_recon_packets(args.count // 8)
    random.shuffle(all_pkts)
    wrpcap(args.output, all_pkts)
    print(f"[Simulator] ✅ {len(all_pkts)} packets → {args.output}")


if __name__ == "__main__":
    main()
