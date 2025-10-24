# AI-Powered IAM Security Scanner

## Features

- **AI-Powered Analysis**: Uses Claude/GPT-4 to understand policy intent, not just syntax
- **Context-Aware**: Considers business context to reduce false positives
- **RAG-Enhanced**: Leverages up-to-date security research via vector database
- **Structured Output**: Guarantees reliable JSON responses using Pydantic + Instructor
- **Async Processing**: Scalable Celery-based task processing
- **PostgreSQL Storage**: Reliable data persistence
- **Redis Caching**: Cost-effective LLM result caching

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │    │  Celery Worker   │    │   PostgreSQL    │
│                 │    │                 │    │                 │
│ • Scan API      │───▶│ • Policy Analysis│───▶│ • Scan Results  │
│ • Progress API  │    │ • AWS Data Fetch │    │ • Findings      │
│ • Config API    │    │ • LLM Processing │    │ • AWS Configs   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│      Redis      │    │    ChromaDB     │    │      AWS       │
│                 │    │                 │    │                 │
│ • Task Queue    │    │ • RAG Knowledge │    │ • IAM Policies  │
│ • Result Cache  │    │ • Security Docs │    │ • Role Assumption│
│ • Progress      │    │ • Best Practices│    │ • Data Fetching │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- AWS credentials configured
- Anthropic or OpenAI API key

### 1. Setup Database

```bash
# Start PostgreSQL
./scripts/setup_db.sh

# Initialize database tables
python scripts/init_db.py
```

### 2. Configure Environment

Create a `.env` file from the sample:

```bash
# Quick setup
./setup_env.sh

# Or manually copy and edit
cp env.sample .env
```

**Required fields to update in `.env`:**

- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (at least one required)
- `SECRET_KEY` (generate a secure random string)

**Optional fields to customize:**

- `DATABASE_URL` (if using different PostgreSQL setup)
- `REDIS_URL` (if using different Redis setup)
- `CHROMADB_URL` (if using different ChromaDB setup)

See `env.sample` for all available configuration options.

### 3. Start Services

```bash
# Start all services with Docker Compose
docker-compose up -d

# Or run locally (requires Redis, PostgreSQL, ChromaDB)
uvicorn main:app --reload
```

### 4. Ingest Knowledge Base

```bash
# Populate RAG system with security knowledge
python scripts/ingest_knowledge.py
```

### 5. Setup AWS Cross-Account Integration

**For each target AWS account you want to scan:**

```bash
# Automated setup (recommended)
./scripts/setup-aws-integration.sh -s YOUR_SCANNER_ACCOUNT_ID -g

```

**Required environment variables:**

- `AWS_EXTERNAL_ID`: Unique identifier for secure role assumption
- `DEFAULT_AWS_ROLE_ARN`: ARN of the scanner role in target account
- `DEFAULT_AWS_ACCOUNT_ID`: Target AWS account ID

See [AWS Integration Setup](docs/aws_integration.md) for detailed instructions.

### 6. Test AWS Integration

```bash
# Test the AWS integration
python scripts/test-aws-integration.py
```

### 7. Trigger a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "scan_name": "Production IAM Scan",
    "targets": ["arn:aws:iam::123456789012:role/MyRole"]
  }'
```

## API Endpoints

### Scans

- `POST /api/v1/scans/trigger` - Start a new scan
- `GET /api/v1/scans/{scan_id}/progress` - Get scan progress
- `GET /api/v1/scans/{scan_id}/insights` - Get scan results and insights

### Configuration

- `POST /api/v1/config/aws` - Configure AWS access
- `GET /api/v1/config/aws/{tenant_id}` - Get AWS configuration

### Health

- `GET /health` - Health check
- `GET /` - API information

## Development

### Local Development Setup

```bash
# Install dependencies
uv pip install -r pyproject.toml

# Start required services
docker-compose up redis postgres chromadb -d

# Run database migrations
python scripts/init_db.py

# Start the application
uvicorn main:app --reload

# Start Celery worker (in another terminal)
celery -A app.tasks.celery_app worker --loglevel=info
```

### Database Management

```bash
# Reset database (WARNING: deletes all data)
./scripts/reset_db.sh

# View database tables
psql postgresql://postgres:postgres@localhost:5432/postgres -c "\dt"
```

### Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=app
```

## Configuration

### Environment Variables

| Variable                  | Description                    | Default                                                  |
| ------------------------- | ------------------------------ | -------------------------------------------------------- |
| `DATABASE_URL`            | PostgreSQL connection string   | `postgresql://postgres:postgres@localhost:5432/postgres` |
| `REDIS_URL`               | Redis connection string        | `redis://localhost:6379/0`                               |
| `CHROMADB_URL`            | ChromaDB server URL            | `http://localhost:8001`                                  |
| `ANTHROPIC_API_KEY`       | Anthropic API key              | None                                                     |
| `OPENAI_API_KEY`          | OpenAI API key                 | None                                                     |
| `MAX_CONCURRENT_ANALYSES` | Max concurrent policy analyses | 5                                                        |
| `CACHE_TTL_SECONDS`       | Cache TTL in seconds           | 2592000 (30 days)                                        |

### AWS Configuration

The scanner uses **cross-account IAM roles** with **ExternalId authentication** for secure access:

#### Security Features

- **Least Privilege**: Read-only IAM permissions
- **ExternalId Required**: Enhanced security with unique identifiers
- **Cross-Account**: Scanner runs in separate account from targets
- **No Write Access**: Cannot modify any AWS resources

#### Required IAM Policy

The scanner role needs read-only access to IAM resources. See `aws-policies/iam-scanner-policy.json` for the complete policy.

#### Setup Process

1. **Automated Setup**: Use `./scripts/setup-aws-integration.sh`
2. **Manual Setup**: Follow [Manual AWS Setup](docs/MANUAL_AWS_SETUP.md) if you have permission issues
3. **Testing**: Use `python scripts/test-aws-integration.py`

#### Environment Variables

```bash
AWS_EXTERNAL_ID=stackguard-scanner-a1b2c3d4e5
DEFAULT_AWS_ROLE_ARN=arn:aws:iam::123456789012:role/StackGuardScannerRole
DEFAULT_AWS_ACCOUNT_ID=123456789012
```

## Architecture Details

### AI Analysis Pipeline

1. **Policy Extraction**: AWS IAM policies are fetched via boto3
2. **Context Enrichment**: RAG system retrieves relevant security knowledge
3. **LLM Analysis**: Claude/GPT-4 analyzes policies with structured output
4. **Caching**: Results are cached to reduce LLM costs
5. **Storage**: Findings are stored in PostgreSQL

### RAG Knowledge Base

The system maintains a vector database of security knowledge including:

- AWS IAM best practices
- OWASP cloud security guidelines
- CIS benchmarks
- Security research papers
- Compliance framework mappings

### Fallback Mechanisms

- **Heuristics Engine**: Rule-based analysis when LLMs fail
- **Cache Layer**: Redis caching for cost optimization
- **Error Handling**: Comprehensive error handling and retry logic

## Monitoring

### Health Checks

```bash
# Check service health
curl http://localhost:8000/health

# Check scan progress
curl http://localhost:8000/api/v1/scans/{scan_id}/progress
```

### Logs

```bash
# View application logs
docker-compose logs -f app

# View worker logs
docker-compose logs -f worker

# View all logs
docker-compose logs -f
```

## Security Considerations

- **API Keys**: Store LLM API keys securely
- **AWS Credentials**: Use IAM roles with minimal permissions
- **Network**: Configure appropriate firewall rules
- **Data**: Encrypt sensitive data at rest and in transit
- **Access**: Implement proper authentication and authorization

## Troubleshooting

### Common Issues

1. **Database Connection Failed**

   ```bash
   # Check PostgreSQL is running
   docker ps | grep postgres

   # Check connection
   psql postgresql://postgres:postgres@localhost:5432/postgres
   ```

2. **Redis Connection Failed**

   ```bash
   # Check Redis is running
   docker ps | grep redis

   # Test connection
   redis-cli ping
   ```

3. **ChromaDB Connection Failed**

   ```bash
   # Check ChromaDB is running
   curl http://localhost:8001/api/v1/heartbeat
   ```

4. **LLM API Errors**
   - Verify API keys are set correctly
   - Check API rate limits
   - Check network connectivity

### Performance Tuning

- Adjust `MAX_CONCURRENT_ANALYSES` based on your infrastructure
- Monitor Redis memory usage
- Tune PostgreSQL connection pool settings
- Consider using multiple Celery workers for high throughput

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
