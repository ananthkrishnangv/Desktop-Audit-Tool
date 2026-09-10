@echo off
title Desktop Security Audit Tool (Native WinUI 3)
echo =====================================================================
echo   Desktop Security Audit Tool - WinUI 3 Native Desktop Application
echo   Tailored for Government, Defense and Research Labs (CSIR, DRDO)
echo =====================================================================
echo.

set EXE_PATH=%~dp0dist\DesktopAuditTool-WinUI-Portable\DesktopAuditTool.WinUI.exe

if not exist "%EXE_PATH%" (
    echo [INFO] Building native WinUI 3 release binary...
    dotnet build "%~dp0src\DesktopAuditTool.WinUI\DesktopAuditTool.WinUI.csproj" -c Release
    mkdir "%~dp0dist\DesktopAuditTool-WinUI-Portable" 2>nul
    xcopy /s /y /q "%~dp0src\DesktopAuditTool.WinUI\bin\Release\net10.0-windows10.0.26100.0\win-x64\*" "%~dp0dist\DesktopAuditTool-WinUI-Portable\" >nul
)

echo [INFO] Launching WinUI 3 Native Desktop Audit Application...
start "" "%EXE_PATH%"
echo [OK] Application launched successfully.
