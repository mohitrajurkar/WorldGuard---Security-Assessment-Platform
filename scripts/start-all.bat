@echo off
echo ============================================================
echo Starting SIH26163 Security Platform (Backend + Frontend)
echo ============================================================

start "SIH Security Backend (Spring Boot)" cmd /k "call "%~dp0start-backend.bat""
timeout /t 3 /nobreak >nul
start "SIH Security Frontend (Vite)" cmd /k "call "%~dp0start-frontend.bat""

echo.
echo Both services are starting:
echo Backend API: http://localhost:8080
echo Frontend UI:  http://localhost:5173
echo.
