@echo off
chcp 65001 >nul
cd /d "%~dp0"
wsl -d Ubuntu --cd "%CD%" --exec ./build/kalyna-lab
pause
