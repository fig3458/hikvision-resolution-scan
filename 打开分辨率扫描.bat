@echo off
chcp 65001 >nul
cd /d "%~dp0"
python scan_gui.py
if errorlevel 1 pause
