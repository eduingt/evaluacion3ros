param(
    [int]$Port = 8765,
    [string]$ListenAddr = "0.0.0.0"
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = Join-Path $root ".venv"
$python = Join-Path (Join-Path $venv "Scripts") "python.exe"
$script = Join-Path $root "dashboard_server.py"

if (-not (Test-Path $python)) {
    Write-Host "[X] No se encuentra $python" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $script)) {
    Write-Host "[X] No se encuentra $script" -ForegroundColor Red
    exit 1
}

# Detener procesos existentes
Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    try { $_.CommandLine -match "dashboard_server.py" } catch { $false }
} | ForEach-Object {
    Write-Host "[*] Deteniendo proceso existente PID: $($_.Id)" -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force
}

Start-Sleep -Seconds 2

# Iniciar nuevo proceso independiente
Write-Host "[*] Iniciando dashboard en http://${ListenAddr}:${Port}/ ..." -ForegroundColor Green
$process = Start-Process -FilePath $python -ArgumentList "dashboard_server.py --port $Port --host $ListenAddr" -WorkingDirectory $root -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 4

# Verificar que responde
try {
    $r = Invoke-WebRequest -Uri "http://${ListenAddr}:${Port}/" -UseBasicParsing -TimeoutSec 5
    Write-Host "[OK] Dashboard respondiendo (Status: $($r.StatusCode)) PID: $($process.Id)" -ForegroundColor Green
    Write-Host "     http://${ListenAddr}:${Port}/"
    Write-Host ""
    Write-Host "[INFO] El servicio seguirá activo incluso si cierras esta ventana de PowerShell." -ForegroundColor Yellow
    Write-Host "[INFO] Para detenerlo manualmente: taskkill /PID $($process.Id) /F" -ForegroundColor Yellow
} catch {
    Write-Host "[!] El proceso se lanzó (PID: $($process.Id)) pero no responde aún." -ForegroundColor Yellow
    Write-Host "[!] Puede tardar unos segundos en iniciar. Verifica en:" -ForegroundColor Yellow
    Write-Host "    http://${ListenAddr}:${Port}/"
}