#!/bin/bash

# Stop and remove existing postgres container if it exists
docker stop postgres 2>/dev/null || true
docker rm postgres 2>/dev/null || true

# Start PostgreSQL container
docker run -d --name postgres \
  -p 5432:5432 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  postgres:latest

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
sleep 5

# Check if container is running
if docker ps | grep -q postgres; then
    echo "✅ PostgreSQL is running at postgresql://postgres:postgres@localhost:5432/postgres"
    echo "Container ID: $(docker ps --filter name=postgres --format '{{.ID}}')"
else
    echo "❌ Failed to start PostgreSQL container"
    exit 1
fi
