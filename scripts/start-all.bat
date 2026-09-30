@echo off
setlocal
echo ============================================================
echo  SIH26163 - Security Assessment Platform
echo ============================================================
echo.

where java >nul 2>&1 || (echo ERROR: Java 21+ not found on PATH. & pause & exit /b 1)
where mvn  >nul 2>&1 || (echo ERROR: Maven not found on PATH. & pause & exit /b 1)
where node >nul 2>&1 || (echo ERROR: Node.js not found on PATH. & pause & exit /b 1)

if not exist "%~dp0..\backend\target\classes" (
  echo Building backend...
  pushd "%~dp0..\backend"
  call mvn -q -DskipTests compile || (popd & pause & exit /b 1)
  popd
)

echo Starting Pentest Suite engine (port 8888)...
start "WorldGuard - Dynamic Engine" cmd /k call "%~dp0start-pentest-suite.bat"
timeout /t 3 /nobreak >nul

echo Starting Spring Boot backend (port 8080)...
start "WorldGuard - Backend API" cmd /k call "%~dp0start-backend.bat"
timeout /t 5 /nobreak >nul

echo Starting React UI (port 5173)...
start "WorldGuard - Web UI" cmd /k call "%~dp0start-frontend.bat"

echo.
echo   UI      : http://localhost:5173
echo   API     : http://localhost:8080
echo   Engine  : http://localhost:8888
echo.
echo Backend uses PostgreSQL by default. To run without a database, set
echo   SPRING_PROFILES_ACTIVE=h2
echo before starting.
echo.
