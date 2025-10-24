#!/bin/bash
# Start Celery worker locally

echo "Starting Celery worker..."

# Check if dependencies are running
if ! docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
    echo "Starting dependencies first..."
    docker-compose -f docker-compose.dev.yml up -d
    sleep 5
fi

# Run Celery worker
celery -A app.tasks.celery_app worker --loglevel=info
