# 🚀 Deploying HAVS on Hostinger VPS

This guide will walk you through the steps to deploy the Hybrid Automated Vulnerability Scanner (HAVS) on a Hostinger VPS (or any Ubuntu-based VPS) using Docker and Nginx.

## Prerequisites

- A Hostinger VPS with Ubuntu 22.04+ (Recommended)
- Docker and Docker Compose installed on the VPS
- At least 2GB of RAM (recommended for the ML model)

## 1. Prepare the VPS

First, log in to your VPS via SSH and install Docker if you haven't already:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install -y docker-compose
```

## 2. Clone the Repository

```bash
git clone https://github.com/your-username/havs.git
cd havs
```

## 3. Configure Environment Variables

Create a `.env` file from the example:

```bash
cp env.example .env
nano .env
```

Add your `NVD_API_KEY` and any other required settings.

## 4. Build and Deploy with Docker Compose

We use separate Dockerfiles for the backend and frontend to ensure a clean and reliable build process.

```bash
# Build and start all services
sudo docker-compose up -d --build
```

This will:
1. Build the React frontend and package it with Nginx.
2. Setup the Python environment and install backend dependencies.
3. Start the FastAPI backend services.
4. Start Nginx to serve the frontend and proxy requests to the backend.

## 5. Access the Application

Once the containers are running, you can access the application:

- **Frontend**: `http://your-vps-ip`
- **Backend API Docs**: `http://your-vps-ip/api/docs`

## 6. Maintenance and Logs

To view logs:
```bash
sudo docker-compose logs -f
```

To stop the services:
```bash
sudo docker-compose down
```

To update the application:
```bash
git pull
sudo docker-compose up -d --build
```

---
> [!IMPORTANT]
> **Firewall Setup**: Ensure that port 80 is open. The internal ports (8000-8002) are proxied by Nginx and don't need to be exposed publicly unless you want direct API access.
> ```bash
> sudo ufw allow 80/tcp
> ```

> [!TIP]
> **Model Loading**: Theแรก time you start the ML service, it might take a minute to load the model binaries. Check `docker-compose logs backend` to monitor the startup progress.
