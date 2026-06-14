# MyTools — Script de instalação (Windows)
# Executa: .\setup.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MyTools v3.2.0 — Instalador" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar Python
Write-Host "[1/4] Verificando Python..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    Write-Host "  OK: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERRO: Python nao encontrado. Instale Python 3.10+ e adicione ao PATH." -ForegroundColor Red
    exit 1
}

# Verificar/Instalar Poetry
Write-Host "[2/4] Verificando Poetry..." -ForegroundColor Yellow
try {
    $poVersion = poetry --version 2>&1
    Write-Host "  OK: $poVersion" -ForegroundColor Green
} catch {
    Write-Host "  Poetry nao encontrado. Instalando..." -ForegroundColor Yellow
    pip install poetry
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao instalar Poetry." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Poetry instalado com sucesso." -ForegroundColor Green
}

# Instalar dependencias
Write-Host "[3/4] Instalando dependencias..." -ForegroundColor Yellow
poetry install --with dev
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERRO: Falha ao instalar dependencias." -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Dependencias instaladas." -ForegroundColor Green

# Adicionar ao PATH
Write-Host "[4/4] Configurando PATH..." -ForegroundColor Yellow
$venvPath = poetry env info --path 2>$null
if (-not $venvPath) {
    Write-Host "  AVISO: Nao foi possivel detectar o venv. Use 'poetry run mytools' para executar." -ForegroundColor Yellow
} else {
    $venvScripts = Join-Path $venvPath "Scripts"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$venvScripts*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$venvScripts", "User")
        Write-Host "  OK: PATH atualizado." -ForegroundColor Green
    } else {
        Write-Host "  OK: PATH ja configurado." -ForegroundColor Green
    }
}

# Resultado
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Instalacao concluida!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Abra um NOVO terminal e execute:" -ForegroundColor Cyan
Write-Host "    mytools --version" -ForegroundColor White
Write-Host "    mytools" -ForegroundColor White
Write-Host ""
Write-Host "  Ou use 'poetry run mytools' neste terminal." -ForegroundColor DarkGray
Write-Host ""
