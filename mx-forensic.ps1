<#
.SYNOPSIS
MX-FORENSIC - Windows Memory & Disk Forensics Tool
.EXAMPLE
.\mx-forensic.ps1 -Ram -Disk "\\.\PhysicalDrive0" -Output "C:\caso"
#>

param(
    [switch]$Ram,
    [string]$Disk,
    [switch]$Hash,
    [switch]$Analyze,
    [switch]$Report,
    [string]$Output = ".\outputs"
)

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Hostname = $env:COMPUTERNAME

Write-Host "[+] MX-FORENSIC iniciado en $Hostname - $Timestamp" -ForegroundColor Green

# Crear directorio de salida
New-Item -ItemType Directory -Force -Path $Output | Out-Null

# RAM DUMP con WinPMEM
if ($Ram) {
    $RamFile = "$Output\ram_${Hostname}_${Timestamp}.raw"
    Write-Host "[*] Dumping RAM a $RamFile ..." -ForegroundColor Yellow
    
    # Descargar WinPMEM si no existe
    $WinPmemPath = ".\tools\winpmem.exe"
    if (-not (Test-Path $WinPmemPath)) {
        Write-Host "[*] Descargando WinPMEM..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Force -Path ".\tools" | Out-Null
        Invoke-WebRequest -Uri "https://github.com/velocidex/winpmem/releases/download/v3.4/winpmem_3.4.exe" -OutFile $WinPmemPath
    }
    
    & $WinPmemPath $RamFile
    Write-Host "[+] RAM dump completado" -ForegroundColor Green
}

# DISK DUMP
if ($Disk) {
    $DiskFile = "$Output\disk_${Hostname}_${Timestamp}.dd"
    Write-Host "[*] Dumping disco $Disk a $DiskFile ..." -ForegroundColor Yellow
    
    # Usar dd para Windows si está disponible, sino usar comando nativo
    $ddPath = ".\tools\dd.exe"
    if (Test-Path $ddPath) {
        & $ddPath if=$Disk of=$DiskFile --progress
    } else {
        Write-Host "[!] dd.exe no encontrado. Instala dd for Windows en .\tools\" -ForegroundColor Red
    }
    Write-Host "[+] Disco dump completado" -ForegroundColor Green
}

# HASHES
if ($Hash) {
    $HashFile = "$Output\hashes_${Timestamp}.txt"
    Write-Host "[*] Calculando hashes..." -ForegroundColor Yellow
    "# Hashes MX-FORENSIC - $Timestamp" | Out-File $HashFile
    
    Get-ChildItem "$Output\*.raw", "$Output\*.dd" -ErrorAction SilentlyContinue | ForEach-Object {
        "=== $($_.Name) ===" | Out-File $HashFile -Append
        $hash = Get-FileHash $_.FullName -Algorithm MD5
        "MD5: $($hash.Hash)" | Out-File $HashFile -Append
        $hash = Get-FileHash $_.FullName -Algorithm SHA1
        "SHA1: $($hash.Hash)" | Out-File $HashFile -Append
        $hash = Get-FileHash $_.FullName -Algorithm SHA256
        "SHA256: $($hash.Hash)" | Out-File $HashFile -Append
        "" | Out-File $HashFile -Append
    }
    Write-Host "[+] Hashes guardados en $HashFile" -ForegroundColor Green
}

# ANÁLISIS SIMPLE (solo strings básico con findstr)
if ($Analyze -and (Test-Path "$Output\ram_*.raw")) {
    $RamDump = Get-ChildItem "$Output\ram_*.raw" | Select-Object -First 1
    $AnalyzeFile = "$Output\analysis_${Timestamp}.txt"
    Write-Host "[*] Analizando RAM dump..." -ForegroundColor Yellow
    
    "=== PROCESOS (strings + findstr) ===" | Out-File $AnalyzeFile
    # En Windows es más limitado sin strings.exe de Sysinternals
    Write-Host "[!] Análisis avanzado requiere strings.exe de Sysinternals en tools/" -ForegroundColor Yellow
}

# REPORTE HTML
if ($Report) {
    $ReportFile = "$Output\reporte_${Timestamp}.html"
    Write-Host "[*] Generando reporte HTML..." -ForegroundColor Yellow
    
    $html = @"
<!DOCTYPE html>
<html>
<head><title>MX-FORENSIC Reporte</title></head>
<body>
<h1>🔍 MX-FORENSIC Reporte</h1>
<p><b>Sistema:</b> $Hostname</p>
<p><b>Fecha:</b> $Timestamp</p>
<h2>Archivos generados</h2>
<ul>
"@
    Get-ChildItem $Output | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        $size = [math]::Round($_.Length / 1MB, 2)
        $html += "<li><code>$($_.Name)</code> - ${size} MB</li>`n"
    }
    $html += "</ul></body></html>"
    $html | Out-File $ReportFile -Encoding UTF8
    Write-Host "[+] Reporte HTML: $ReportFile" -ForegroundColor Green
}

Write-Host "[+] MX-FORENSIC finalizado. Resultados en $Output" -ForegroundColor Green
