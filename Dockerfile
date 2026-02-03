FROM python:3.11-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install backend dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code and model
COPY backend/ ./backend/
COPY ml_model/ ./ml_model/
COPY scripts/ ./scripts/
COPY .env.example ./.env

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 8000 8001 8002

# Environment variables
ENV PYTHONUNBUFFERED=1

# Run the production startup script
CMD ["bash", "scripts/start_prod.sh"]
