@echo off
echo ============================================================
echo Starting SIH26163 Security Platform Backend (Spring Boot 3)
echo ============================================================

set "JAVA_HOME=C:\Program Files\JetBrains\IntelliJ IDEA 2026.2.2\jbr"
set "PATH=%JAVA_HOME%\bin;D:\tools\apache-maven-3.9.6\bin;%PATH%"

cd /d "%~dp0..\backend"
mvn spring-boot:run
