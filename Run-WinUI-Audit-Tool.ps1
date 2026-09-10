# Desktop Security Audit Tool - WinUI 3 Native Desktop Application
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Desktop Security Audit Tool - WinUI 3 Native Desktop Application" -ForegroundColor Green
Write-Host "  Tailored for Government, Defense and Research Labs (CSIR, DRDO)" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Cyan

$exePath = Join-Path $PSScriptRoot "dist\DesktopAuditTool-WinUI-Portable\DesktopAuditTool.WinUI.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "[INFO] Building native WinUI 3 release binary..." -ForegroundColor Yellow
    dotnet build (Join-Path $PSScriptRoot "src\DesktopAuditTool.WinUI\DesktopAuditTool.WinUI.csproj") -c Release
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "dist\DesktopAuditTool-WinUI-Portable") -Force | Out-Null
    Copy-Item -Path (Join-Path $PSScriptRoot "src\DesktopAuditTool.WinUI\bin\Release\net10.0-windows10.0.26100.0\win-x64\*") -Destination (Join-Path $PSScriptRoot "dist\DesktopAuditTool-WinUI-Portable") -Recurse -Force
}

Write-Host "[INFO] Launching WinUI 3 Native Desktop Audit Application..." -ForegroundColor Cyan
Start-Process -FilePath $exePath
Write-Host "[OK] WinUI 3 application launched successfully." -ForegroundColor Green
