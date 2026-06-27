#!/bin/bash
# UEBA Microservice Startup Script

cd "$(dirname "$0")"

# Set environment variables
export UEBA_PORT=5001
export UEBA_HOST=0.0.0.0
export DB_PATH="/home/ubuntu/soar-dashboard/wazuh_alerts.db"

# Activate virtual environment if exists
if [ -d "../venv" ]; then
    source ../venv/bin/activate
fi

# Install required packages if not present
pip install flask flask-cors numpy scipy 2>/dev/null

# Start the service
echo "Starting UEBA Microservice on port $UEBA_PORT..."
python app.py
