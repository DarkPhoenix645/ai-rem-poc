FROM python:3.13-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY pyproject.toml .
COPY main.py .
COPY README.md .
COPY app/ ./app/
COPY scripts/ ./scripts/

# Install dependencies
RUN uv pip install --system .

# Set PYTHONPATH to ensure imports work
ENV PYTHONPATH=/app

# Create non-root user
RUN useradd --create-home --shell /bin/bash scanner
USER scanner

EXPOSE 8000

# Production command (use gunicorn with uvicorn workers)
CMD ["gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4"]
