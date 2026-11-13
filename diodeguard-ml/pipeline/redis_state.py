"""
Redis Sliding-Window State Manager
Maintains per-source-IP counters, rates, and entropy stats
over a configurable time window using Redis sorted sets + hashes.
"""

import os
import time
import math
from collections import Counter
from typing import Optional

import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))  # 5-minute window


class SlidingWindowState:
    def __init__(self, window_sec: int = WINDOW_SECONDS):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.window = window_sec

    def record_flow(self, src_ip: str, dst_port: int, pkt_count: int, byte_count: int):
        """Record a new flow and update all sliding-window counters."""
        now = time.time()
        cutoff = now - self.window

        pipe = self.r.pipeline()

        # Flow count per src over window (sorted set by timestamp)
        flow_key = f"flows:{src_ip}"
        pipe.zadd(flow_key, {f"{now}:{dst_port}": now})
        pipe.zremrangebyscore(flow_key, 0, cutoff)
        pipe.expire(flow_key, self.window + 10)

        # Bytes accumulator
        bytes_key = f"bytes:{src_ip}"
        pipe.incrbyfloat(bytes_key, byte_count)
        pipe.expire(bytes_key, self.window)

        # Packets accumulator
        pkts_key = f"pkts:{src_ip}"
        pipe.incrbyfloat(pkts_key, pkt_count)
        pipe.expire(pkts_key, self.window)

        # Destination port set (for recon detection)
        ports_key = f"dst_ports:{src_ip}"
        pipe.sadd(ports_key, dst_port)
        pipe.expire(ports_key, self.window)

        pipe.execute()

    def get_flow_stats(self, src_ip: str) -> dict:
        """Return aggregated stats for a source IP over the sliding window."""
        now = time.time()
        cutoff = now - self.window

        pipe = self.r.pipeline()
        flow_key = f"flows:{src_ip}"
        pipe.zrangebyscore(flow_key, cutoff, now)
        pipe.get(f"bytes:{src_ip}")
        pipe.get(f"pkts:{src_ip}")
        pipe.scard(f"dst_ports:{src_ip}")
        results = pipe.execute()

        flows_in_window, total_bytes_str, total_pkts_str, unique_ports = results
        total_bytes = float(total_bytes_str or 0)
        total_pkts = float(total_pkts_str or 0)
        flow_count = len(flows_in_window)

        # Compute dst_port entropy from recent flows
        ports = [entry.split(":")[1] for entry in flows_in_window if ":" in entry]
        port_entropy = self._entropy(ports)

        return {
            "flow_count_per_src_5min": flow_count,
            "bytes_per_sec": total_bytes / self.window,
            "packets_per_sec": total_pkts / self.window,
            "unique_dst_ports": int(unique_ports),
            "dst_port_entropy": port_entropy,
        }

    def _entropy(self, values: list) -> float:
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        return -sum((c / total) * math.log2(c / total + 1e-9) for c in counts.values())

    def ping(self) -> bool:
        try:
            return self.r.ping()
        except Exception:
            return False


if __name__ == "__main__":
    state = SlidingWindowState()
    if state.ping():
        print("✅ Redis connected")
        state.record_flow("192.168.1.1", 80, 100, 50000)
        stats = state.get_flow_stats("192.168.1.1")
        print(f"Stats: {stats}")
    else:
        print("❌ Redis not available")
