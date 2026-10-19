@echo off
rem Prints the one-time setup token of the Tenko service (Start menu: Tenko setup token).
rem The token lives in the data directory, which only administrators, SYSTEM and the
rem service account can read, so the script asks for elevation when it does not have it.
net session >nul 2>&1
if errorlevel 1 (
  set "TENKO_SELF=%~f0"
  powershell.exe -NoProfile -Command "Start-Process -Verb RunAs -FilePath $env:ComSpec -ArgumentList ('/c \"' + $env:TENKO_SELF + '\"')"
  exit /b
)
"%~dp0tenko.exe" setup token --config "%ProgramData%\Tenko\tenko.toml"
echo.
echo Open https://localhost:8443 (or the host name of this server) and enter the token.
echo It changes at every start of the service until setup is complete.
echo.
pause
