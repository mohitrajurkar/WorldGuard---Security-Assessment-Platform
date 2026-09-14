@echo off
echo ============================================================
echo Starting SIH26163 Security Platform Frontend (Vite + React)
echo ============================================================

set "PATH=C:\Program Files\nodejs;%PATH%"

cd /d "%~dp0..\frontend"
npm run dev
