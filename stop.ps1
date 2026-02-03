# Stop HAVS Services
Write-Host "Stopping HAVS Services..." -ForegroundColor Yellow

$ports = @(8000, 8001, 8002, 5173)

foreach ($port in $ports) {
    $processes = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($processes) {
        foreach ($proc in $processes) {
            try {
                $id = $proc.OwningProcess
                $p = Get-Process -Id $id -ErrorAction SilentlyContinue
                if ($p) {
                    Write-Host "Killing process on port $port (PID: $id - $($p.ProcessName))..." -ForegroundColor Gray
                    Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
                }
            } catch {
                # Ignore errors
            }
        }
    }
}

Write-Host "All services stopped." -ForegroundColor Green
