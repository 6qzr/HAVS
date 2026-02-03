#!/usr/bin/env python3
"""
Main entry point to start all microservices
Starts Dependency Scanner, ML Analysis, and Main API services
"""

import subprocess
import sys
import time
import signal
import os
from pathlib import Path

# Service configurations
SERVICES = [
    {
        "name": "Dependency Scanner Service",
        "module": "backend.services.dependency_scanner:app",
        "port": 8001,
        "icon": "📦"
    },
    {
        "name": "ML Analysis Service",
        "module": "backend.services.ml_analysis:app",
        "port": 8002,
        "icon": "🤖"
    },
    {
        "name": "Main API",
        "module": "backend.api:app",
        "port": 8000,
        "icon": "🌐",
        "reload": True  # Enable auto-reload for main API
    }
]

processes = []

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully stop all services"""
    print("\n\n🛑 Stopping all services...")
    for process in processes:
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception:
            pass
    print("✅ All services stopped")
    sys.exit(0)

def check_port_available(port):
    """Check if a port is available"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result != 0

def start_service(service_config):
    """Start a single service"""
    name = service_config["name"]
    module = service_config["module"]
    port = service_config["port"]
    icon = service_config.get("icon", "🔧")
    reload = service_config.get("reload", False)
    
    # Check if port is available
    if not check_port_available(port):
        print(f"⚠️  Port {port} is already in use. Skipping {name}")
        return None
    
    # Build uvicorn command
    cmd = [
        sys.executable, "-u", "-m", "uvicorn",
        module,
        "--host", "0.0.0.0",
        "--port", str(port)
    ]

    
    if reload:
        cmd.append("--reload")
    
    print(f"{icon} Starting {name} (Port {port})...")
    
    # Use log files instead of pipes to avoid hangs when buffers fill up
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file_path = log_dir / f"{name.lower().replace(' ', '_')}.log"
    
    try:
        log_file = open(log_file_path, "a", encoding="utf-8")
        log_file.write(f"\n\n--- Starting {name} at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        log_file.flush()
        
        # Start process
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=log_file,
            text=True
        )
        
        # Wait a bit to check if it started successfully
        time.sleep(2)
        
        if process.poll() is None:
            print(f"   ✅ {name} started (PID: {process.pid})")
            print(f"      Logs: {log_file_path}")
            return process
        else:
            print(f"   ❌ {name} failed to start")
            print(f"      Check logs: {log_file_path}")
            return None
            
    except Exception as e:
        print(f"   ❌ Failed to start {name}: {e}")
        return None

def main():
    """Main function to start all services"""
    print("🚀 Starting Vulnerability Scanner Microservices...")
    print("")
    
    # Check if Python is available
    if not sys.executable:
        print("❌ Python is not available")
        sys.exit(1)
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start all services
    for service in SERVICES:
        process = start_service(service)
        if process:
            processes.append(process)
        time.sleep(1)  # Small delay between starts
    
    if not processes:
        print("\n❌ No services started. Please check for errors above.")
        sys.exit(1)
    
    print("")
    print("✅ All services started!")
    print("")
    print("Services:")
    for service in SERVICES:
        port = service["port"]
        name = service["name"]
        print(f"  - {name}: http://localhost:{port}")
    print("")
    print("API Documentation:")
    print("  - Main API Docs: http://localhost:8000/docs")
    print("")
    print("Press Ctrl+C to stop all services")
    print("")
    
    # Keep script running and monitor processes
    try:
        while True:
            # Check if any process has died
            for i, process in enumerate(processes):
                if process.poll() is not None:
                    service_name = SERVICES[i]["name"]
                    print(f"⚠️  {service_name} has stopped unexpectedly")
                    processes.remove(process)
            
            if not processes:
                print("\n❌ All services have stopped")
                break
            
            time.sleep(5)  # Check every 5 seconds
            
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()

