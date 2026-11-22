@echo off
setlocal enabledelayedexpansion

echo ==========================================================
echo  Haylou Watch 4S - Drag & Drop Pure-Image Watchface Maker
echo ==========================================================

set PROJECT_DIR=%~dp0
set IMG_PATH=%~1

if "%IMG_PATH%"=="" (
    echo.
    echo [INFO] Drag and drop any PNG/JPG/WEBP image onto this file,
    echo        OR paste the full path to an image below and press Enter:
    echo.
    set /p IMG_PATH="Image path: "
)

set IMG_PATH=%IMG_PATH:"=%
if not exist "%IMG_PATH%" (
    echo.
    echo [ERROR] Image not found: "%IMG_PATH%"
    pause
    exit /b 1
)

echo.
echo [*] Checking connected Android phone via ADB...
adb get-state 1>nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] No Android phone detected over ADB!
    echo         1. Connect phone with USB cable
    echo         2. Enable USB Debugging in Developer Options
    echo         3. Unlock phone and tap "Allow" if prompted
    pause
    exit /b 1
)

echo [*] Ensuring Haylou Fun cache folder exists on phone...
adb shell "mkdir -p /sdcard/Android/data/com.yingsheng.hayloufun/cache" 2>nul

echo [*] Building clockless 466x466 Watch 4S .bin and pushing to phone...
python "%PROJECT_DIR%scripts\watchface_bin_maker.py" "%IMG_PATH%" --push

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build or push failed. Make sure Python and Pillow are installed:
    echo         pip install -r "%PROJECT_DIR%requirements.txt"
    pause
    exit /b 1
)

echo.
echo ==========================================================
echo  SUCCESS! Now finish on your phone (5 seconds):
echo  1. Open Haylou Fun (make sure Watch 4S is connected)
echo  2. Go to Device -^> Dial Center / Watch Face Market
echo  3. Tap ANY free cloud watchface and tap "Sync / Install"
echo  4. Your custom pure-image watchface will install!
echo ==========================================================
echo.
pause
