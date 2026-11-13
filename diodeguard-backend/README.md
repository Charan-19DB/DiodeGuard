# DiodeGuard — FastAPI Backend (Track B)

## Overview
REST API backend for DiodeGuard. Handles:
- JWT authentication + RBAC (Admin / Analyst roles)
- Flow ingestion and retrieval
- Detection result management
- Alert CRUD + acknowledgement
- Dashboard aggregation endpoints
- User management (Admin only)

## Setup

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
```

## Environment Variables
```bash
cp .env.example .env
# Edit .env with your PostgreSQL URL and JWT secret
```

## Run Development Server
```bash
uvicorn app.main:app --reload
# API docs: http://localhost:8000/docs
```

## Run Tests
```bash
pytest tests/ -v --cov=app
```

## Run Database Migrations
```bash
alembic upgrade head
```

## Directory Structure
```
diodeguard-backend/
├── app/
│   ├── main.py           # FastAPI app entry point
│   ├── database.py       # SQLAlchemy engine + session
│   ├── models/           # ORM models (users, flows, alerts, detection_models)
│   ├── schemas/          # Pydantic request/response schemas
│   ├── routers/          # API route handlers
│   ├── services/         # Business logic layer
│   ├── middleware/        # RBAC + logging middleware
│   └── core/             # Config, security utils (JWT, hashing)
├── alembic/              # DB migration files
└── tests/                # pytest test suite
```
