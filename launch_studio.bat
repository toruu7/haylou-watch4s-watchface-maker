@echo off
setlocal
cd /d "%~dp0"
echo Starting Haylou Watch 4S Studio...

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo [ERROR] Python was not found on your PATH.
  echo         Install Python 3.9+ from https://www.python.org/downloads/
  echo         and tick "Add Python to PATH" during setup.
  pause
  exit /b 1
)

python -c "import PIL" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo [*] Installing the Python dependency (Pillow)...
  python -m pip install -r requirements.txt
  if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Could not install Pillow. Check your Python installation.
    pause
    exit /b 1
  )
)

python studio\server.py
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo [ERROR] Studio stopped with an error. Set STUDIO_LOG=1 for request logs.
  pause
)
