<#
.SYNOPSIS
    SheetSafe AI — Local Development & Presentation Demo Launcher (Windows PowerShell)

.DESCRIPTION
    Launches the SheetSafe AI local demonstration environment for the Vultr Agent Rush Hackathon.
    Connects Streamlit UI (port 8501) to FastAPI control plane (port 8000) using server-owned
    synthetic demonstration fixtures and deterministic simulated AI planning.

    DOES NOT make live cloud API calls, provision VMs, start Docker containers,
    or execute untrusted Python code.

.PARAMETER Component
    The service component to launch:
      - 'fastapi'   : Start the FastAPI control-plane service (http://127.0.0.1:8000)
      - 'streamlit' : Start the Streamlit interactive dashboard (http://127.0.0.1:8501)
      - 'setup-env' : Idempotently provision .env.local with safe loopback settings
      - 'help'      : Print launch commands and troubleshooting guidance

.EXAMPLE
    # Terminal 1 (FastAPI backend):
    .\launch_local_demo.ps1 -Component fastapi

    # Terminal 2 (Streamlit dashboard):
    .\launch_local_demo.ps1 -Component streamlit
#>

[CmdletBinding()]
param(
    [ValidateSet("fastapi", "streamlit", "setup-env", "help")]
    [string]$Component = "help"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Locate approved Python executable
$ApprovedVenvPython = Join-Path $ProjectRoot "var\runtime-validation-31317\venv\Scripts\python.exe"
$StandardVenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (Test-Path -LiteralPath $ApprovedVenvPython) {
    $PythonExe = $ApprovedVenvPython
} elseif (Test-Path -LiteralPath $StandardVenvPython) {
    $PythonExe = $StandardVenvPython
} else {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonExe) {
        Write-Error "Python executable not found. Please activate your virtual environment or install Python 3.12+."
        exit 1
    }
}

function Ensure-LocalEnv {
    $EnvLocalPath = Join-Path $ProjectRoot ".env.local"
    if (-not (Test-Path -LiteralPath $EnvLocalPath)) {
        Write-Host "Creating local loopback configuration: $EnvLocalPath" -ForegroundColor Cyan
        $LocalEnvContent = @"
# SheetSafe AI — Local Demonstration Settings (Loopback Only)
SHEETSAFE_ENVIRONMENT=development
SHEETSAFE_ALLOWED_ORIGINS=["http://localhost:8501","http://127.0.0.1:8501","http://127.0.0.1:8000","http://localhost:8000"]
SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES=true
SHEETSAFE_SYNTHETIC_PLANNING_ENABLED=true
SHEETSAFE_DOCS_ENABLED=false
SHEETSAFE_DATABASE_PATH=var/sheetsafe.sqlite3
SHEETSAFE_SESSION_LIFETIME_SECONDS=3600
"@
        Set-Content -LiteralPath $EnvLocalPath -Value $LocalEnvContent -Encoding UTF8
        Write-Host "Local configuration saved successfully." -ForegroundColor Green
    } else {
        Write-Host "Found existing .env.local configuration." -ForegroundColor Gray
    }
}

switch ($Component) {
    "setup-env" {
        Ensure-LocalEnv
        Write-Host "Environment is ready for local demonstration." -ForegroundColor Green
    }

    "fastapi" {
        Ensure-LocalEnv
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host " Starting SheetSafe AI FastAPI Backend (127.0.0.1:8000)..." -ForegroundColor Cyan
        Write-Host " Press Ctrl+C to shut down cleanly." -ForegroundColor Gray
        Write-Host "==========================================================" -ForegroundColor Cyan
        & $PythonExe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
    }

    "streamlit" {
        Ensure-LocalEnv
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host " Starting SheetSafe AI Streamlit Dashboard (127.0.0.1:8501)..." -ForegroundColor Cyan
        Write-Host " Press Ctrl+C to shut down cleanly." -ForegroundColor Gray
        Write-Host "==========================================================" -ForegroundColor Cyan
        & $PythonExe -m streamlit run (Join-Path $ProjectRoot "frontend\app.py") --server.address 127.0.0.1 --server.port 8501
    }

    "help" {
        Ensure-LocalEnv
        Write-Host ""
        Write-Host "=== SheetSafe AI — Local Demo Startup Instructions ===" -ForegroundColor Green
        Write-Host ""
        Write-Host "To run the full presentation demo, open TWO PowerShell terminals:"
        Write-Host ""
        Write-Host "  Terminal 1 (Start FastAPI backend):" -ForegroundColor Yellow
        Write-Host "    .\launch_local_demo.ps1 -Component fastapi"
        Write-Host ""
        Write-Host "  Terminal 2 (Start Streamlit UI):" -ForegroundColor Yellow
        Write-Host "    .\launch_local_demo.ps1 -Component streamlit"
        Write-Host ""
        Write-Host "  Browser URL:" -ForegroundColor Yellow
        Write-Host "    http://localhost:8501"
        Write-Host ""
        Write-Host "  To stop services:" -ForegroundColor Yellow
        Write-Host "    Press Ctrl+C in each terminal."
        Write-Host ""
        Write-Host "=== Troubleshooting ===" -ForegroundColor Cyan
        Write-Host "  - Port Conflict : If port 8000 or 8501 is busy, stop previous processes with Get-Process."
        Write-Host "  - 403 Forbidden : Verify SHEETSAFE_ALLOWED_ORIGINS in .env.local contains http://localhost:8501."
        Write-Host "  - Offline Status: Ensure Terminal 1 (FastAPI) is running before testing the dashboard."
        Write-Host ""
    }
}

