#!/bin/bash

echo "🚀 Setting up AI-Powered IAM Security Scanner..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "📝 Checking if .env exists..."
    if [ -f .env ]; then
        echo "✅ .env exists"
        echo "⚠️  Please ensure the required fields in .env:"
        echo "   - ANTHROPIC_API_KEY or OPENAI_API_KEY (at least one required)"
        echo "   - SECRET_KEY (secure random string)"
    else
        echo "❌ .env not found. Please create it first."
        exit 1
    fi
fi

# Start PostgreSQL
echo "🐘 Starting PostgreSQL..."
if ./scripts/setup_db.sh; then
    echo "✅ PostgreSQL setup completed"
else
    echo "❌ PostgreSQL setup failed"
    exit 1
fi

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 3

# Initialize database
echo "🗄️ Initializing database tables..."
if python scripts/init_db.py; then
    echo "✅ Database initialization completed"
else
    echo "❌ Database initialization failed"
    exit 1
fi

# Start all services
echo "🐳 Starting all services with Docker Compose..."
if docker-compose up -d; then
    echo "✅ Docker Compose started successfully"
    
    # Wait for services to be ready
    echo "⏳ Waiting for services to initialise..."
    sleep 10
    
    # Check service health
    echo "🔍 Checking service health..."
    if curl -s http://localhost:8000/health > /dev/null; then
        echo "✅ API is healthy"
    else
        echo "❌ API health check failed"
        echo "🔧 Check logs with: docker-compose logs app"
        exit 1
    fi
else
    echo "❌ Failed to start Docker Compose services"
    echo "🔧 Check logs with: docker-compose logs"
    exit 1
fi

# Ingest knowledge base
echo "📚 Ingesting security knowledge base..."
if python scripts/ingest_knowledge.py; then
    echo "✅ Knowledge base ingestion completed"
else
    echo "❌ Knowledge base ingestion failed"
    echo "⚠️  Continuing without knowledge base (some features may be limited)"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Configure AWS access:"
echo "   curl -X POST http://localhost:8000/api/v1/config/aws \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"aws_account_id\": \"123456789012\", \"aws_role_to_assume_arn\": \"arn:aws:iam::123456789012:role/ScannerRole\"}'"
echo ""
echo "2. Trigger a scan:"
echo "   curl -X POST http://localhost:8000/api/v1/scans/trigger \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"scan_name\": \"Test Scan\"}'"
echo ""
echo "3. View API documentation: http://localhost:8000/docs"
echo ""
