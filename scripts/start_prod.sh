#!/bin/bash
# Production Startup Script for HAVS Backend Services
# This script starts all microservices using Gunicorn with Uvicorn workers

# Ensure we are in the project root
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$ROOT_DIR"

# Create logs directory if it doesn't exist
mkdir -p logs

echo "🚀 Starting HAVS Backend Services in Production Mode..."

# 1. Start Dependency Scanner Service (Port 8001)
echo "📦 Starting Dependency Scanner Service..."
gunicorn backend.services.dependency_scanner:app \
    --workers 2 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8001 \
    --daemon \
    --access-logfile logs/dependency_scanner_access.log \
    --error-logfile logs/dependency_scanner_error.log

# 2. Start ML Analysis Service (Port 8002)
# Using fewer workers for ML as it's CPU/memory intensive
echo "🤖 Starting ML Analysis Service..."
gunicorn backend.services.ml_analysis:app \
    --workers 1 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8002 \
    --daemon \
    --access-logfile logs/ml_analysis_access.log \
    --error-logfile logs/ml_analysis_error.log

# 3. Start Main API (Port 8000)
echo "🌐 Starting Main API..."
gunicorn backend.api:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --access-logfile logs/main_api_access.log \
    --error-logfile logs/main_api_error.log

echo "✅ All backend services started!"
