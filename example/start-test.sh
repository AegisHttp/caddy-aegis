#!/bin/bash

# kill any existing processes on port 3000, 4000, 3003 just in case
fuser -k 4000/tcp 2>/dev/null
fuser -k 5173/tcp 2>/dev/null
fuser -k 3003/tcp 2>/dev/null

echo "🚀 Starting Backend (Port 4000)..."
cd backend
go run main.go &
BACKEND_PID=$!
cd ..

echo "🌐 Starting Frontend (Port 5173)..."
cd frontend
go run main.go &
FRONTEND_PID=$!
cd ..

echo "🛡️ Starting Caddy Server with Aegis HTTP (Port 3003)..."
# We assume the user has the built caddy binary in this folder as per instructions
if [ -f "./caddy" ]; then
    ./caddy run --config caddy.json &
    CADDY_PID=$!
else
    echo "⚠️ Warning: 'caddy' binary not found in 'example' directory. Did you build it with xcaddy?"
fi

echo ""
echo "✅ Everything is running!"
echo "   - Frontend is at: http://localhost:5173"
echo "   - Backend is at: http://localhost:4000"
echo "   - Caddy Proxy is at: http://localhost:3003"
echo ""
echo "Press [CTRL+C] to stop all servers."

# Wait indefinitely, kill children on exit
trap "kill -9 $BACKEND_PID $FRONTEND_PID $CADDY_PID 2>/dev/null" SIGINT SIGTERM EXIT
wait
