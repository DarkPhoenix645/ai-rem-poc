#!/bin/bash
# Development setup script

echo "Starting development dependencies..."

# Start only the dependencies
docker-compose -f docker-compose.dev.yml up -d

echo "Waiting for services to be ready..."
sleep 10

# Check if services are running
echo "Checking service status..."
docker-compose -f docker-compose.dev.yml ps

echo ""
echo "Services started! You can now run the app locally:"
echo ""
echo "1. Install dependencies locally:"
echo "   pip install -e ."
echo ""
echo "2. Set up environment variables:"
echo "   cp env.sample .env"
echo "   # Edit .env with your API keys"
echo ""
echo "3. Run the FastAPI app:"
echo "   uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "4. Run Celery worker (in another terminal):"
echo "   celery -A app.tasks.celery_app worker --loglevel=info"
echo ""
echo "5. To stop dependencies:"
echo "   docker-compose -f docker-compose.dev.yml down"
