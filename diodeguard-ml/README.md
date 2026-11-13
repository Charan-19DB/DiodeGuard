# DiodeGuard — ML Pipeline & Data Engineering (Track A)

## Overview
This repository contains the entire ML pipeline for DiodeGuard:
- Traffic simulation (Scapy PCAP generator)
- Stream replay (Kafka producer)
- Feature extraction (NFStream)
- Redis sliding-window state
- Six threat detection models
- Alert emitter (writes to PostgreSQL)

## Setup

```bash
# Requires WSL2 or Linux (NFStream not native on Windows)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Environment Variables
Copy `.env.example` to `.env` and fill in values:
```bash
cp .env.example .env
```

## Usage

### 1. Prepare Datasets
```bash
python scripts/prepare_datasets.py
```

### 2. Train All Models
```bash
python models/train_all.py
```

### 3. Generate Demo Traffic
```bash
python traffic_sim/generate_traffic.py --output data/demo.pcap
```

### 4. Replay Traffic into Kafka
```bash
python ingest/stream_replay.py --pcap data/demo.pcap --rate 500
```

### 5. Run the Detection Pipeline
```bash
python pipeline/detector.py
```

## Run Tests
```bash
pytest tests/ -v --cov=pipeline --cov=models
```

## Directory Structure
```
diodeguard-ml/
├── datasets/          # Raw + processed data (gitignored)
├── scripts/           # Data prep + feature engineering
├── models/            # ML model trainers + saved .joblib files
├── pipeline/          # Kafka consumer → extractor → detector → emitter
├── traffic_sim/       # Scapy-based PCAP generator
├── ingest/            # Stream replay (Kafka producer)
└── tests/             # Unit + integration tests
```
