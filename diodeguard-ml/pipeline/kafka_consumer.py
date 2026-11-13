"""
Kafka Consumer + Main Pipeline Loop
Reads flow records from Kafka → extracts features → detects threats → emits alerts.
"""

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
KAFKA_GROUP = os.getenv("KAFKA_GROUP", "diodeguard-detector")


def run_pipeline():
    from pipeline.detector import DiodeGuardDetector
    from pipeline.alert_emitter import init_tables, emit_alert, emit_flow
    from pipeline.redis_state import SlidingWindowState

    try:
        from kafka import KafkaConsumer
        kafka_available = True
    except ImportError:
        kafka_available = False

    init_tables()
    detector = DiodeGuardDetector()
    state = SlidingWindowState()

    print(f"[Pipeline] Starting. Kafka: {KAFKA_BOOTSTRAP}, Topic: {KAFKA_TOPIC}")

    if not kafka_available:
        print("[Pipeline] kafka-python not installed — running in DEMO mode with synthetic flows")
        _demo_loop(detector, state, emit_alert, emit_flow)
        return

    consumer = None
    retries = 30
    while retries > 0:
        try:
            consumer = KafkaConsumer(
                KAFKA_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=KAFKA_GROUP,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            )
            print(f"[Pipeline] ✅ Kafka consumer connected. Listening on '{KAFKA_TOPIC}'...")
            break
        except Exception as e:
            print(f"[Pipeline] Waiting for Kafka broker at {KAFKA_BOOTSTRAP} ({e})... {retries} retries left")
            time.sleep(3)
            retries -= 1

    if consumer is None:
        print("[Pipeline WARN] Kafka broker unreachable after retries — falling back to DEMO loop.")
        _demo_loop(detector, state, emit_alert, emit_flow)
        return
    flow_count = 0
    alert_count = 0

    for message in consumer:
        try:
            flow = message.value
            if not isinstance(flow, dict):
                continue
            flow.setdefault("flow_id", str(uuid.uuid4()))
            flow.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

            # Update Redis sliding-window state
            state.record_flow(
                src_ip=flow.get("src_ip", "0.0.0.0"),
                dst_port=int(flow.get("dst_port", 0)),
                pkt_count=int(flow.get("packets_per_sec", 0)),
                byte_count=int(flow.get("bytes_per_sec", 0)),
            )
            window_stats = state.get_flow_stats(flow.get("src_ip", "0.0.0.0"))
            flow.update(window_stats)

            emit_flow(flow)
            alerts = detector.score_flow(flow)
            for alert in alerts:
                emit_alert(alert)
                alert_count += 1
                print(f"  🚨 ALERT [{alert['severity']}] {alert['threat_class']} "
                      f"conf={alert['confidence_score']:.2f} src={alert['src_ip']}")

            flow_count += 1
            if flow_count % 100 == 0:
                print(f"[Pipeline] Processed {flow_count} flows, {alert_count} alerts total")
        except Exception as err:
            print(f"[Pipeline WARN] Skipped faulty message: {err}")


def _demo_loop(detector, state, emit_alert, emit_flow):
    """Fallback demo loop generating synthetic flows when Kafka is unavailable."""
    import random
    print("[Pipeline] Demo mode: generating synthetic flows every second...")
    templates = [
        {"packets_per_sec": 18000, "bytes_per_sec": 9e7, "src_ip_entropy": 0.95,
         "dst_port_entropy": 0.05, "syn_ratio": 0.95, "udp_ratio": 0.0, "icmp_ratio": 0.0,
         "flow_duration": 0.8, "packet_size_mean": 60, "packet_size_std": 5},
        {"inter_arrival_mean": 60, "inter_arrival_std": 0.5, "inter_arrival_cv": 0.008,
         "flow_duration": 2.0, "bytes_per_pkt": 128, "dst_port": 4444,
         "unique_dst_ports_per_src": 1, "flow_count_per_src_5min": 4},
    ]
    for i in range(100):
        flow = random.choice(templates).copy()
        flow["flow_id"] = f"demo-{i:04d}"
        flow["src_ip"] = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        flow["dst_ip"] = "203.0.113.5"
        flow["src_port"] = random.randint(1024, 65535)
        flow["dst_port"] = flow.get("dst_port", 80)
        flow["protocol"] = "TCP"
        flow["timestamp"] = datetime.now(timezone.utc).isoformat()
        emit_flow(flow)
        alerts = detector.score_flow(flow)
        for alert in alerts:
            emit_alert(alert)
            print(f"  🚨 [{alert['severity']}] {alert['threat_class']} conf={alert['confidence_score']:.2f}")
        time.sleep(0.1)
    print("[Pipeline] Demo complete.")


if __name__ == "__main__":
    run_pipeline()
