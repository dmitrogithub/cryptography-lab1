@echo off
cd /d "%~dp0"
wsl -d Ubuntu --cd "%CD%" --exec bash scripts/build.sh
pause
