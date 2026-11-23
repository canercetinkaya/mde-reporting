@echo off
REM ============================================================
REM  MDE Managed EDR Reporting
REM  Kurulum baslatici
REM  Yurutme politikasini yalnizca bu oturum icin devre disi
REM  birakir ve indirilen dosyalarin engelini kaldirir.
REM ============================================================
title MDE Reporting - Kurulum Sihirbazi

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-ChildItem -Path '%~dp0' -Filter *.ps1 | Unblock-File; Get-ChildItem -Path '%~dp0' -Filter *.cmd | Unblock-File"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-MDEReport.ps1"

echo.
pause
