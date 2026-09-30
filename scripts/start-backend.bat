@echo off
setlocal
cd /d "%~dp0..\backend"
if "%SPRING_PROFILES_ACTIVE%"=="" (
  mvn spring-boot:run
) else (
  mvn spring-boot:run "-Dspring-boot.run.profiles=%SPRING_PROFILES_ACTIVE%"
)
