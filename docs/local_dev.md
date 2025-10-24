# Local Development Setup

Quick guide for running the app locally with Docker dependencies only.

## Quick Start

```bash
# 1. Start dependencies
docker-compose -f docker-compose.dev.yml up -d

# 2. Install Python dependencies
uv sync

# 3. Configure environment
cp env.dev .env
source .venv/bin/activate

# 4. Run application (2 terminals)
./scripts/run-app.sh      # Terminal 1: FastAPI
./scripts/run-worker.sh   # Terminal 2: Celery worker
```

## What Runs Where

**Docker (Dependencies Only):**

- Redis: `localhost:6379`
- ChromaDB: `localhost:8001`
- PostgreSQL: `localhost:5432`

**Local (Application):**

- FastAPI: `localhost:8000`
- Celery Worker: Background tasks

## Benefits

✅ **Fast Development**: No Docker build times  
✅ **Hot Reload**: Code changes reflect immediately  
✅ **Easy Debugging**: Direct Python debugger access  
✅ **IDE Integration**: Full breakpoint support

## Commands

```bash
# Dependencies
docker-compose -f docker-compose.dev.yml up -d
docker-compose -f docker-compose.dev.yml down
docker-compose -f docker-compose.dev.yml logs -f

# Application
./scripts/run-app.sh
./scripts/run-worker.sh

# Knowledge Base Setup
python scripts/setup_knowledge_base.py
```

## Troubleshooting

**Port Conflicts:**

```bash
lsof -i :8000 :6379 :5432 :8001
```

**Database Tests:**

```bash
psql postgresql://postgres:postgres@localhost:5432/postgres
redis-cli ping
curl http://localhost:8001/api/v1/heartbeat
```

**Python Issues:**

```bash
export PYTHONPATH=$PWD:$PYTHONPATH
```

## Environment Variables

Required in `.env`:

```bash
# API Keys (at least one required)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# Database URLs (defaults work for Docker)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
REDIS_URL=redis://localhost:6379/0
CHROMADB_URL=http://localhost:8001
```

## Next Steps

1. **Setup Knowledge Base**: `python scripts/setup_knowledge_base.py`
2. **Test API**: `curl http://localhost:8000/health`
3. **View Docs**: http://localhost:8000/docs
