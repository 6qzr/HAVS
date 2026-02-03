# HAVS Startup Script for Windows
# Simplified version - uses Ctrl+C to stop

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Starting HAVS Application" -ForegroundColor Cyan
Write-Host "=========================================="
Write-Host ""

# Set encoding to UTF-8 to support emojis in output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# Check if .env exists
if (-not (Test-Path ".env")) {
    Write-Warning ".env file not found!"
    Write-Host "Creating from template..."
    if (Test-Path "env.example") {
        Copy-Item "env.example" ".env"
        Write-Host "Created .env - Please edit and add your NVD_API_KEY" -ForegroundColor Green
        exit
    }
}

# Load .env file into environment variables
Write-Host "Loading environment variables from .env..." -ForegroundColor Gray
Get-Content ".env" | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)\s*=\s*(.*)$') {
        $name = $matches[1].Trim()
        $value = $matches[2].Trim()
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        Write-Host "  Loaded: $name" -ForegroundColor DarkGray
    }
}

# Resolve Python Executable
$pythonCmd = "python"
if (Get-Command "python3" -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
}

# Check if specific path exists (optional override)
$specificPython = "C:\Users\Strik\AppData\Local\Programs\Python\Python311\python.exe"
if (Test-Path $specificPython) {
    $pythonCmd = $specificPython
}

Write-Host "Using Python: $pythonCmd" -ForegroundColor Gray

# Verify ML Dependencies
Write-Host "Verifying ML dependencies..." -ForegroundColor Gray
$checkDeps = & $pythonCmd -c "import torch; import transformers; print('ok')" 2>&1
if ($checkDeps -notmatch "ok") {
    Write-Warning "ML dependencies (torch, transformers) not found or failed to load."
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & $pythonCmd -m pip install -r requirements.txt
    
    # Re-check
    $checkDeps = & $pythonCmd -c "import torch; import transformers; print('ok')" 2>&1
    if ($checkDeps -notmatch "ok") {
        Write-Error "Failed to install/load ML dependencies. ML features may not work."
        Write-Host "Error details: $checkDeps" -ForegroundColor Red
        # Continue anyway, but user is warned
    } else {
        Write-Host "Dependencies installed successfully." -ForegroundColor Green
    }
} else {
    Write-Host "ML dependencies verified." -ForegroundColor Green
}

# Node check
try {
    $nodeVersion = node --version 2>&1
    Write-Host "Using Node.js: $nodeVersion" -ForegroundColor Gray
} catch {
    Write-Error "Node.js not found! Please install Node.js."
    exit
}

Write-Host ""
Write-Host "Starting Backend Services..." -ForegroundColor Yellow
Write-Host "=========================================="

# Start backend in a new window with environment variables
# We use cmd /k with set commands to ensure env vars are passed
$envVars = "set PYTHONIOENCODING=utf-8"
if ($env:NVD_API_KEY) {
    $envVars += " && set NVD_API_KEY=$env:NVD_API_KEY"
}
$backendCmd = "$envVars && `"$pythonCmd`" backend/main.py"
Start-Process -FilePath "cmd" -ArgumentList "/k $backendCmd" -WorkingDirectory $PWD
Write-Host "Backend starting..." -ForegroundColor Green

# Wait for backend to initialize
Write-Host "Waiting for backend to initialize (10 seconds)..."
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "Starting Frontend..." -ForegroundColor Yellow
Write-Host "=========================================="

Push-Location "fyp_dashboard"

# Check node_modules
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
    npm install
}

# Start frontend in a new window
Start-Process -FilePath "cmd" -ArgumentList "/k npm run dev" -WorkingDirectory $PWD
Write-Host "Frontend starting..." -ForegroundColor Green

Pop-Location

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Application Started!" -ForegroundColor Cyan
Write-Host "=========================================="
Write-Host ""
Write-Host "Services:"
Write-Host "  - Backend API: http://localhost:8000"
Write-Host "  - API Docs:    http://localhost:8000/docs"
Write-Host "  - Frontend:    http://localhost:5173"
Write-Host ""
Write-Host "Backend and Frontend are running in separate windows." -ForegroundColor Yellow
Write-Host "Close those windows to stop the services." -ForegroundColor Yellow
