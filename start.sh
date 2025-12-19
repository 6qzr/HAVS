#!/bin/bash
# Application Startup Script - Starts both frontend and backend services

echo "=========================================="
echo "Starting FYP_2025 Application"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found!"
    echo "Creating from template..."
    if [ -f "env.example" ]; then
        cp env.example .env
        echo "✓ Created .env - Please edit and add your NVD_API_KEY"
        exit 1
    fi
fi

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Verify API key
if [ -z "$NVD_API_KEY" ]; then
    echo "⚠️  Warning: NVD_API_KEY not set (will use limited rate)"
fi

echo ""
echo "Starting Backend Services..."
echo "=========================================="

# Start backend in background
python3 backend/main.py &
BACKEND_PID=$!

# Wait for backend to start
echo "Waiting for backend to initialize..."
sleep 5

echo ""
echo "Starting Frontend..."
echo "=========================================="

# Check if node_modules exists
if [ ! -d "fyp_dashboard/node_modules" ]; then
    echo "Installing frontend dependencies..."
    cd fyp_dashboard && npm install && cd ..
fi

# Start frontend
cd fyp_dashboard
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "=========================================="
echo "✅ Application Started!"
echo "=========================================="
echo ""
echo "Services:"
echo "  - Backend API: http://localhost:8000"
echo "  - Frontend:    http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down services..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "✓ Services stopped"
    exit 0
}

# Trap SIGINT (Ctrl+C) and cleanup
trap cleanup SIGINT

# Wait for both processes
wait

