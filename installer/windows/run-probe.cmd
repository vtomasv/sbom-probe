@echo off
"%~dp0sbom-probe.exe" run -config "%~dp0config.json" -watch >> "%~dp0logs\probe.log" 2>&1
exit /b %errorlevel%
