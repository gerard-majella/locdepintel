@echo off
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" || (
  echo LocDepIntel needs Python 3.11 or newer. Install it from https://www.python.org/downloads/
  pause
  exit /b 1
)
py -3 -m locdepintel serve %*
pause
