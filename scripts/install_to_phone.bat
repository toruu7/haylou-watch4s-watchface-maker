@echo off
setlocal enabledelayedexpansion

echo ==========================================================
echo  Haylou Watch 4S - One-Click Modded App Installer
echo ==========================================================

set SCRIPT_DIR=%~dp0
set APK_PATH=%SCRIPT_DIR%..\haylou-fun-v4-0-8-noclock.apk
if not exist "%APK_PATH%" (
    set APK_PATH=%USERPROFILE%\Downloads\haylou-fun-v4-0-8-noclock.apk
)

if not exist "%APK_PATH%" (
    echo [ERROR] Modded APK not found! Please run patch_and_build_apk.py first.
    pause
    exit /b 1
)

echo [*] Checking ADB connection...
adb devices
echo.

echo [*] Installing %APK_PATH% to connected Android device...
adb install -r "%APK_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo [!] Standard install failed. Attempting uninstall + clean install...
    adb uninstall com.yingsheng.hayloufun
    adb install "%APK_PATH%"
)

if %ERRORLEVEL% EQU 0 (
    echo [+] Successfully installed!
    echo [*] Launching Haylou Fun...
    adb shell "am start -n com.yingsheng.hayloufun/com.liesheng.hayloufun.SplashActivity"
    echo [SUCCESS] App is running on your phone!
) else (
    echo [ERROR] Installation failed. Ensure USB debugging is active and device is authorized.
)

pause
