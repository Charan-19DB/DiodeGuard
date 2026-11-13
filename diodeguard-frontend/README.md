# DiodeGuard — React Security Dashboard (Track C) 🛡️

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**  
*Prototype for SIH26145 — National Technical Research Organisation (NTRO)*

---

## Overview

The DiodeGuard frontend is an analyst-grade, high-performance security operations center (SOC) dashboard built to run inside an isolated passive monitoring enclave.

### Features
- **Live Security Dashboard:** Real-time polling with summary cards, live event timelines, traffic throughput charts, and threat distribution analytics.
- **Alerts Feed:** Live streaming and acknowledgement of high-confidence threats with detailed evidence inspection and status filtering.
- **Threat Intelligence:** In-depth breakdown of classified threats (DDoS, Botnet C2, DGA, Encrypted Malware, Recon, Exfiltration).
- **Network Traffic Explorer:** Raw unidirectional flow inspection and ingress statistics.
- **Reports & Intelligence Export:** JSON reporting export and historical time-series analytics.
- **User & Access Management:** Admin-only user role provisioning and access control.
- **Offline / Mock Mode:** Built-in rich mock data simulation (`VITE_USE_MOCK=true`) allowing full standalone testing without requiring backend or database infrastructure.

---

## Tech Stack
- **Framework:** React 19 + Vite 8
- **Styling:** Custom Cyber-Sovereign Dark Theme (Pure Vanilla CSS, CSS Custom Properties, Glassmorphism, Micro-animations)
- **Charts:** Recharts
- **Routing:** React Router v7
- **Deployment:** Docker (Node build + Nginx Alpine reverse proxy)

---

## Getting Started

### Prerequisites
- Node.js 20+
- npm or yarn

### Installation
```bash
# Navigate to track directory
cd diodeguard-frontend

# Install dependencies
npm install
```

### Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VITE_API_URL` | `http://localhost:8000` | Backend API base address |
| `VITE_USE_MOCK` | `true` | When `true`, uses mock SOC telemetry for offline preview |

### Development Server
```bash
npm run dev
```
Open `http://localhost:5173` in your browser.

### Production Build & Preview
```bash
npm run build
npm run preview
```

### Docker Deployment
```bash
docker build -t diodeguard-frontend .
docker run -p 5173:80 diodeguard-frontend
```

---

## Default Demo Credentials
When running in Mock mode, click **"Instant Demo Access (Admin)"** on the login page, or use:
- **Email:** `admin@diodeguard.local`
- **Password:** `DemoAdmin2026!`
