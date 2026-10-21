@echo off
powershell.exe -NoProfile -File "%~dp0install.ps1" %*
exit /b %ERRORLEVEL%
