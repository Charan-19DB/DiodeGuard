# DiodeGuard 🛡️ — System Architecture, Tech Stack & Strategic Plan

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**  
*Prototype for SIH26145 — National Technical Research Organisation (NTRO)*  
*Theme: Blockchain & Cybersecurity / Critical Information Infrastructure (CII) Protection*  
*Classification: Technical Whitepaper & Operational Blueprint*  
*Document Version: 1.0.0 · Publication Date: October 2026*

---

## Executive Summary

**DiodeGuard** is a specialized, artificial intelligence-driven network security and cyber threat detection system engineered specifically to operate inside a **strictly passive, unidirectional monitoring enclave**. It is connected to the monitored network via a physical **Hardware Data Diode** or a passive optical network tap.

In critical national infrastructure (CNI) such as defense installations, nuclear power facilities, power grid control centers (SCADA/ICS), and high-security government networks, data diodes are deployed to guarantee that data can only travel outward (or into an isolated analysis enclave) with 100% physical certainty. Because the hardware physically omits or severs the transmit (Tx) optical fiber, **no return packet, TCP ACK, ICMP reply, or active probe can ever be transmitted back to the source network**.

While this physical design prevents external attackers from traversing the diode into the protected network, it presents a fundamental dilemma: **traditional network intrusion detection systems (NIDS) and Security Operations Center (SOC) tooling rely heavily on bidirectional TCP handshakes, return-path state tracking, and active verification**. Without return traffic, traditional tools either flood analysts with false positives or completely fail to detect stealthy cyber threats.

**DiodeGuard solves this challenge** by:
1. Re-engineering network flow analysis around **forward-only behavioral indicators**.
2. Maintaining temporal sliding-window state in-memory via high-throughput **Redis sorted sets**.
3. Applying **six threat-specific Machine Learning and Deep Learning models** to detect both known weaponized attacks and anomalous zero-day campaigns.
4. Cryptographically verifying model integrity via **SHA-256 digests** to prevent adversarial poisoning in air-gapped enclaves.
5. Providing security analysts with a low-latency, real-time **SOC Operations Dashboard** featuring sub-second alerting, deep evidence inspection, and automated reporting.

---

## 1. Problem Statement & The Unidirectional Challenge

### 1.1 What is a Hardware Data Diode?
A hardware data diode is a physical cybersecurity boundary device consisting of a transmitter photodiode coupled to a receiver photodiode via an optical fiber. Unlike software firewalls, which can be misconfigured, bypassed, or exploited via zero-day vulnerabilities, a data diode enforces unidirectional physical isolation at Layer 1 of the OSI model:
- **Physical Rx-Only Receiver:** The receiver hardware physically lacks a light-emitting diode (LED) or laser transmitter.
- **Physical Invariant:** Light—and therefore data—can only travel in a single direction. Transmitting a signal backward is physically impossible.

### 1.2 Why Traditional Network Security Tools Fail on Data Diodes
Conventional intrusion detection and security systems (e.g., inline IPS, traditional Snort/Suricata bidirectional rules, Zeek connection tracking, honeypots) are built on bidirectional assumptions:
- **TCP Handshake Breakdown:** Conventional engines wait for a complete `SYN -> SYN-ACK -> ACK` 3-way handshake to establish connection state. In unidirectional capture, only one side of the conversation is visible. Traditional tools flag every TCP session as an incomplete, broken, or suspicious connection.
- **Active Scanning Infeasibility:** Defenses cannot initiate active probes, banner grabs, honeypot replies, or TCP resets (`RST`) to confirm or disrupt malicious hosts.
- **Bi-directional Flow Statistics Absence:** Traditional metrics like round-trip time (RTT), TCP window adjustments, retransmission counters, and client-to-server vs. server-to-client payload ratios are either unavailable or distorted.
- **Beaconing and Stealth C2 Blindness:** Attackers using periodic Command and Control (C2) heartbeat pulses or covert DNS tunneling blend into ambient noise if an analyst cannot observe the server's command responses.

---

## 2. DiodeGuard Architecture & The Three Tracks

DiodeGuard decouples ingestion, real-time machine learning inference, enterprise data persistence, and visualization across three modular, independently testable tracks:

```
[ Dirty / Monitored Network ]
             │ (Raw Optical Tap / SPAN)
             ▼
     ┌──────────────┐
     │  Hardware    │
     │  Data Diode  │ (Physical Rx-only fiber, Tx photodiode physically removed)
     └──────┬───────┘
            │
            ▼ (Unidirectional Ingest)
┌────────────────────────────────────────────────────────────────────────┐
│ Passive Monitoring Enclave                                             │
│                                                                        │
│  [Network Sniffer / Replayer] ──> Kafka Topic: "unidirectional-traffic"│
│                                                  │                     │
│                                                  ▼                     │
│                                          [ML Pipeline]                 │
│                                        (Track A: ML Engine)            │
│                                                  │                     │
│                                                  ▼                     │
│                                      PostgreSQL / REST API             │
│                                        (Track B: Backend)              │
│                                                  │                     │
│                                                  ▼                     │
│                                      [React Dashboard]                 │
│                                       (Track C: Frontend)              │
└────────────────────────────────────────────────────────────────────────┘
```

### Track Breakdown

| Track | Module | Primary Responsibility | Core Technologies |
| :--- | :--- | :--- | :--- |
| **Track A** | `diodeguard-ml` | Traffic generation, NFStream feature extraction, Redis sliding-window state, 6 AI threat detection models, Kafka consumer pipeline | Python 3.11, NFStream, Scapy, Scikit-learn, Redis, Kafka, Joblib, NumPy, Pandas |
| **Track B** | `diodeguard-backend` | REST API, PostgreSQL database persistence, Alembic migrations, JWT Auth & RBAC, Flow/Alert lifecycle management | Python 3.11, FastAPI, SQLAlchemy ORM, Alembic, PostgreSQL 16, Pydantic |
| **Track C** | `diodeguard-frontend` | Security Operations Center (SOC) dashboard, telemetry charts, alert triage & acknowledgement, traffic explorer, mock mode | React 19, Vite 8, Recharts, React Router v7, Vanilla CSS, Docker / Nginx |

---

## 3. Machine Learning & Detection Model Taxonomy

DiodeGuard employs a **hybrid detection paradigm**: supervised classification for known attack signatures where structured telemetry exists, and unsupervised anomaly detection for zero-day, stealthy reconnaissance and exfiltration activities.

| Model / Threat Class | Learning Paradigm | Primary Algorithm | Target Threat Vectors | Key Engineered Features | Severity Mapping |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. DDoS** | Supervised | Random Forest (200 trees, max depth 12) / LightGBM | SYN flood, UDP flood, ICMP reflection, volumetric saturation | `packets_per_sec`, `bytes_per_sec`, `src_ip_entropy`, `dst_port_entropy`, `syn_ratio`, `packet_size_mean`, `packet_size_std` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |
| **2. Botnet C2 Beaconing** | Supervised + Windowed State | Random Forest + Redis sliding-window state tracking | Cobalt Strike, Emotet, Mirai beaconing, zombie bot heartbeats | `inter_arrival_mean`, `inter_arrival_std`, `inter_arrival_cv` (coefficient of variation), `flow_count_per_src_5min`, `bytes_per_pkt` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |
| **3. DGA & DNS Tunnelling** | Lexical Supervised | Random Forest (300 trees, max depth 15) | Domain Generation Algorithms (Tor/malware C2), DNS data exfiltration | `domain_length`, `digit_ratio`, `consonant_ratio`, `entropy`, `n_gram_score`, `subdomain_count`, `ttl_mean` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |
| **4. Encrypted Session Malware** | Metadata Supervised | Random Forest + JA3 hash catalog | Trojan droppers, ransomware over TLS 1.2/1.3 without payload decryption | `ja3_known_bad`, `tls_version_numeric`, `cert_validity_days`, `cert_self_signed`, `sni_entropy`, `bytes_per_sec`, `packet_size_std` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |
| **5. Reconnaissance & Port Scanning** | Unsupervised Anomaly | Isolation Forest (contamination=0.05) | Nmap SYN scans, horizontal sweeps, vertical sweeps, stealth idle scans | `unique_dst_ports`, `unique_dst_ips`, `syn_no_ack_ratio`, `scan_rate`, `rst_ratio`, `bytes_per_pkt` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |
| **6. Data Exfiltration** | Unsupervised Anomaly | Extended Isolation Forest | Covert HTTP/S POST exfiltration, large data spills, slow-and-low staging | `upload_bytes`, `download_bytes`, `upload_download_ratio`, `entropy_payload`, `dns_query_length_mean`, `http_post_ratio` | Medium: 0.75-0.85<br>High: 0.85-0.92<br>Critical: >0.92 |

### 3.1 Redis Sliding-Window State Manager
Because unidirectional traffic cannot rely on connection termination flags (`FIN` / `RST`), DiodeGuard introduces a memory-efficient temporal state manager using Redis sorted sets:
- **Time Windows:** 300-second (5-minute) rolling windows keyed by source IP (`flows:<src_ip>`).
- **Pruning:** Out-of-window timestamps are removed using `ZREMRANGEBYSCORE` with atomic pipelines.
- **Statistical Aggregations:** Computes rolling packet rates, byte volumes, unique destination port carding (`SCARD`), and Shannon port entropy across time slices.

### 3.2 Cryptographic Model Integrity
To prevent adversarial tampering in air-gapped enclaves:
- Every trained model artifact (`.joblib`) is paired with an SHA-256 digest (`<model_name>_hash.txt`).
- Upon startup in `detector.py`, the engine computes the SHA-256 digest of the serialized model bytes.
- If any discrepancy is detected, the pipeline halts immediately with a security alert, preventing adversarial backdoor execution.

---

## 4. Comprehensive Technology Stack

| Layer | Component / Tool | Version | Purpose in DiodeGuard |
| :--- | :--- | :--- | :--- |
| **Ingress & Replay** | **Scapy** | 2.5.0 | Synthetic packet crafting, attack injection, and realistic PCAP generation |
| | **NFStream** | 6.5.3 | High-speed network flow extraction, deep L7 protocol metadata extraction |
| | **Apache Kafka** | 7.6.1 | Distributed streaming broker decoupling packet ingress from AI model workers |
| | **Apache Zookeeper**| 3.8.4 | Kafka cluster synchronization and partition state management |
| **Temporal State** | **Redis** | 7.2 | Sliding-window in-memory state tracking, entropy calculation, rate accumulators |
| **Machine Learning** | **Scikit-learn** | 1.4.1 | Random Forest, Isolation Forest, model evaluation, and cross-validation |
| | **LightGBM / XGBoost**| Latest | Gradient-boosted decision trees for high-velocity volumetric DDoS classification |
| | **Joblib** | 1.3.2 | Fast serialization and deserialization of trained model pipelines |
| | **NumPy & Pandas** | 2.2 / 2.0 | High-performance feature vector formatting, array manipulation, and parquet storage |
| **Backend & API** | **FastAPI** | 0.110.0 | High-performance asynchronous REST API framework with automatic OpenAPI docs |
| | **Uvicorn** | 0.28.0 | ASGI web server for production backend serving |
| | **SQLAlchemy** | 2.0.28 | Modern asynchronous and synchronous Object Relational Mapper (ORM) |
| | **Alembic** | 1.13.1 | Database schema migrations and version-controlled database revisions |
| | **PostgreSQL** | 16-alpine | Enterprise relational storage for flows, threats, alerts, model metrics, and users |
| | **Pydantic** | 2.6.4 | Strict runtime data validation, schema enforcement, and serialization |
| | **PyJWT + Passlib** | 2.8.0 | Cryptographic JWT token generation, verification, and bcrypt password hashing |
| **Frontend & UI** | **React** | 19.0.0 | Modern declarative UI component framework for the SOC analyst dashboard |
| | **Vite** | 8.0.0 | Next-generation ultra-fast frontend build tooling and HMR dev server |
| | **Recharts** | 2.12.0 | Responsive SVG telemetry charting (time series, radar charts, bar breakdowns) |
| | **React Router** | 7.0.0 | Client-side routing for seamless page navigation across dashboard views |
| | **Vanilla CSS** | Modern | Bespoke Cyber-Sovereign dark design system with glassmorphism and custom properties |
| | **Nginx** | 1.25-alpine| High-concurrency reverse proxy serving production frontend builds in Docker |
| **Orchestration** | **Docker & Compose**| v2 / 3.9 | Single-command deployment (`docker compose up --build`) across 7 isolated containers |

---

## 5. How DiodeGuard is Useful (Value Proposition & Real-World Impact)

### 5.1 Enforcing Zero-Return Security Invariants
In classified environments (NTRO, defense command posts, intelligence enclaves), leaking even a single ACK or ICMP error packet across a perimeter boundary could give an attacker the confirmation needed to complete an exploit. DiodeGuard guarantees **100% passive monitoring**—it consumes incoming streams without sending a single outbound electrical or optical pulse.

### 5.2 Protection of Critical National Infrastructure (CNI)
- **Power Grids & Nuclear Facilities (SCADA/ICS):** Industrial control systems often use data diodes to send sensor telemetry from Operational Technology (OT) networks to IT networks. DiodeGuard detects malicious injection, command spoofing, or malware staging without placing OT devices at risk.
- **Defense Communications:** Protects classified message buses from unauthorized exfiltration and covert C2 channels.
- **Financial Clearinghouses & Stock Exchanges:** Analyzes high-velocity financial market feeds for rogue data injection or denial-of-service attempts.

### 5.3 Automated Real-Time Threat Triage & Evidence Provenance
When an alert triggers, human SOC analysts cannot run active port scans or traceroutes to investigate. DiodeGuard provides instant **explainable evidence** right inside the alert payload:
- Model name and confidence score (e.g., `ddos_lightgbm_v1`, confidence `0.945`).
- Exact contributing features (e.g., `packets_per_sec: 12450`, `syn_ratio: 0.98`).
- Heuristic alert flags (e.g., `HIGH_SYN_BURST`, `LOW_DST_PORT_ENTROPY`).
- One-click SOC analyst acknowledgement and historical audit logging.

### 5.4 Inspection of Encrypted Threats Without Decryption
Modern cyber adversaries encrypt 90%+ of their payload using TLS 1.3. Decrypting packets requires private key exposure or active SSL interception (MITM), which is physically impossible across a data diode. DiodeGuard analyzes **unencrypted handshake metadata**—JA3/JA3S client fingerprints, certificate validity life spans, SNI entropy, and packet size distributions—to pinpoint ransomware droppers and Trojans without ever needing decryption keys.

### 5.5 High Operational Efficiency & Resilience
- **Offline Mock Capability:** DiodeGuard includes a built-in simulation mode (`VITE_USE_MOCK=true`) enabling team training, offline demos, and air-gapped staging without requiring live network traffic.
- **Low Footprint & High Throughput:** With Kafka streaming buffers, Redis in-memory windows, and vectorized scikit-learn models, DiodeGuard processes thousands of flows per second on commodity server hardware.

---

## 6. End-to-End Implementation & Rollout Roadmap

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     Phase 1     │     │     Phase 2     │     │     Phase 3     │     │     Phase 4     │
│  Prototype &    │ ──> │ Hardware Enclave│ ──> │ eBPF & 40G Line │ ──> │ Production CNI  │
│  Model Training │     │  & Integration  │     │ Rate Ingestion  │     │  Hardening &    │
│    (Complete)   │     │ (Months 1 - 3)  │     │ (Months 4 - 6)  │     │ FIPS Compliance │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Phase 1: Prototype Validation & Model Tuning (Current State ✅)
- Built the 3-track decoupled architecture (`diodeguard-ml`, `diodeguard-backend`, `diodeguard-frontend`).
- Implemented and trained all 6 threat detection models with SHA-256 cryptographic hashing.
- Constructed Kafka consumer pipeline, Redis sliding-window state manager, and PostgreSQL schema.
- Designed analyst-grade SOC dashboard with dark-mode aesthetic and mock simulation mode.
- Validated via end-to-end Docker Compose stack.

### Phase 2: Hardware Enclave & Tap Integration (Months 1–3)
- Physical integration with commercial hardware data diodes (e.g., Advenica, Owl Cyber Defense, or customized NTRO optical splitters).
- Implement hardware flow offloading and test line-rate capture on 1 Gbps / 10 Gbps optical fiber interfaces.
- Integrate Zeek / Suricata passive log exporters to feed the `unidirectional-traffic` Kafka topic.

### Phase 3: eBPF & Kernel-Bypass Ingestion (Months 4–6)
- Transition flow extraction to Linux eBPF (Extended Berkeley Packet Filter) and DPDK (Data Plane Development Kit) for ultra-low-latency, zero-copy packet processing.
- Scale Redis caching into a clustered in-memory mesh to support multi-million concurrent flow tracking.
- Train online semi-supervised anomaly models that periodically re-tune to shifting baseline network behavior.

### Phase 4: Production Hardening, FIPS Compliance & Threat Sharing (Months 7–12)
- FIPS 140-3 cryptographic module validation for all hashing, JWT, and data-at-rest encryption.
- STIX/TAXII threat intelligence exporter (routed exclusively through an authorized outbound data diode to external defense centers).
- Role-based automated reporting (Executive PDF summaries, compliance audit logs, CSV telemetry exports).

---

## 7. Quick Start & Verification Guide

### 7.1 Instant Full-Stack Launch via Docker
To spin up all 7 microservices in a single command:
```bash
docker compose up --build
```

**Service Topology & Ports:**
- **SOC Analyst Dashboard:** `http://localhost:5173`
- **FastAPI Backend Documentation:** `http://localhost:8000/docs`
- **PostgreSQL Database:** `localhost:5432` (Database: `diodeguard`, User: `diodeguard`)
- **Apache Kafka Broker:** `localhost:9092`
- **Redis Cache:** `localhost:6379`

### 7.2 Standalone Development Commands

#### 1. Machine Learning Engine (`diodeguard-ml`):
```bash
cd diodeguard-ml
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scripts/prepare_datasets.py
python models/train_all.py
python ingest/stream_replay.py --pcap data/demo.pcap --rate 500
python pipeline/detector.py
pytest tests/ -v
```

#### 2. Backend REST API (`diodeguard-backend`):
```bash
cd diodeguard-backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
pytest tests/ -v
```

#### 3. Frontend Dashboard (`diodeguard-frontend`):
```bash
cd diodeguard-frontend
npm install
npm run dev
# Live at http://localhost:5173
```
*Demo Login: `admin@diodeguard.local` / `DemoAdmin2026!` or click "Instant Demo Access"*

---

## 8. Conclusion

DiodeGuard addresses a critical gap in modern national defense and cybersecurity for critical infrastructure. By transforming passive, unidirectional network streams into rich behavioral feature vectors and applying specialized AI models, DiodeGuard delivers **uncompromising threat visibility without sacrificing the physical air-gap guarantee of hardware data diodes**.
