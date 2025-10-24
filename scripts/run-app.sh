#!/bin/bash
# Start FastAPI app locally

echo "Starting FastAPI app..."

# Check if dependencies are running
if ! docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
    echo "Starting dependencies first..."
    docker-compose -f docker-compose.dev.yml up -d
    sleep 5
fi

# Run FastAPI with hot reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000
