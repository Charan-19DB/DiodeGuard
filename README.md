# DiodeGuard 🛡️

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**  
*Prototype for SIH26145 — National Technical Research Organisation (NTRO)* · Theme: Blockchain & Cybersecurity

---

## 1. Executive Summary

DiodeGuard is an AI/ML-based cyber threat detection system designed to operate strictly inside a **passive, read-only monitoring enclave** — fed by a physical hardware data diode or passive optical network tap.

Because hardware data diodes physically forbid packet transmission back to the source network, traditional bidirectional security mechanisms (TCP handshakes, active probing, honeypots, inline IPS) cannot function. DiodeGuard solves this by extracting forward-flow behavioral features, maintaining sliding-window state in-memory, and scoring network flows across **six threat-specific ML models**.

---

## 2. Architecture & The Three Tracks

To enable modular development and clean team handoffs, the project is structured into three independent repositories:

| Repository / Track | Responsibility | Tech Stack |
| :--- | :--- | :--- |
| **[diodeguard-ml](./diodeguard-ml)** (Track A) | Traffic simulation, flow feature extraction, Redis sliding-window state, 6 AI detection models, Kafka consumer pipeline | Python 3.11, Scapy, NFStream, Scikit-learn, LightGBM, XGBoost, Kafka, Redis |
| **[diodeguard-backend](./diodeguard-backend)** (Track B) | REST API, PostgreSQL ORM, Alembic migrations, JWT Auth, RBAC, flow & alert persistence | Python 3.11, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Pydantic |
| **[diodeguard-frontend](./diodeguard-frontend)** (Track C) | SOC analyst dashboard, real-time telemetry charts, alert management, mock mode | React 19, Vite, Recharts, Vanilla CSS, Docker / Nginx |

For full data schemas, message topics, and REST contracts, see **[CONTRACTS.md](./CONTRACTS.md)**.

---

## 3. Quick Start (Full Stack via Docker)

You can spin up the entire end-to-end environment (Zookeeper, Kafka, Redis, PostgreSQL, ML Pipeline, Backend, and Frontend) with one command:

```bash
docker compose up --build
```

### Service Map
| Service | Internal Port | Host Port | Description |
| :--- | :--- | :--- | :--- |
| **Frontend** | 80 | `http://localhost:5173` | React Security Operations Dashboard |
| **Backend API** | 8000 | `http://localhost:8000` | FastAPI Swagger Docs: `/docs` |
| **PostgreSQL** | 5432 | `localhost:5432` | Relational storage for flows and alerts |
| **Kafka Broker** | 9092 | `localhost:9092` | Unidirectional traffic stream |
| **Redis** | 6379 | `localhost:6379` | Sliding-window state for C2 beaconing |

---

## 4. Standalone Development per Track

Each repository can be developed and tested independently:

### Track A — ML Pipeline
```bash
cd diodeguard-ml
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scripts/prepare_datasets.py
python models/train_all.py
pytest tests/ -v
```

### Track B — Backend API
```bash
cd diodeguard-backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
pytest tests/ -v
```

### Track C — Frontend Dashboard
```bash
cd diodeguard-frontend
npm install
npm run dev
# Live at http://localhost:5173 (runs standalone in mock mode by default)
```

---

## 5. Security & Isolation Guarantee
DiodeGuard enforces strict read-only unidirectional safety:
1. No TCP ACK or egress transmission is ever sent across the monitored ingress link.
2. In-memory state tracking operates without return-path signaling.
3. Model artifacts use cryptographic SHA-256 integrity validation upon startup.
