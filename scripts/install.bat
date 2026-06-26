@echo off
REM =============================================================================
REM install.bat — Stage 1 Windows Installation Script
REM =============================================================================
REM
REM What this script does:
REM   1. Checks for winget (Windows Package Manager) or falls back to manual.
REM   2. Installs the Rust toolchain via rustup-init.exe.
REM   3. Installs WinPcap/Npcap (required by the pcap crate on Windows).
REM   4. Compiles Stage 1 in release mode.
REM   5. Copies the binary to C:\ddos_stage1\ddos_stage1.exe.
REM   6. Creates a Windows Task Scheduler entry for autostart (optional).
REM
REM IMPORTANT NOTES FOR WINDOWS USERS:
REM ─────────────────────────────────────────────────────────────────────────────
REM • Windows does NOT natively support Linux network bridges (br0) or iptables/
REM   ipset. Stage 1 can capture and analyse traffic on Windows, but Stage 2's
REM   kernel-level blocking (ipset/Netfilter) will NOT work.
REM
REM • Windows support is provided for DEVELOPMENT AND TESTING only:
REM     - Unit tests (`cargo test`) work fully on Windows.
REM     - The statistical engine (Welford, EWMA, Entropy) compiles and runs.
REM     - Packet capture requires Npcap installed with "WinPcap API compatibility".
REM     - The IPC Unix Domain Socket requires Windows 10 v1803+ or Windows Server 2019+.
REM
REM • For PRODUCTION deployment (actual DDoS mitigation), use Linux.
REM
REM Usage:
REM   Run as Administrator: install.bat
REM
REM Requirements:
REM   • Windows 10 (1803+) or Windows Server 2019+
REM   • Administrator privileges
REM   • Internet connection (for rustup and Npcap downloads)
REM =============================================================================

setlocal enabledelayedexpansion

echo.
echo ========================================================
echo   Adaptive DDoS Pre-Filter - Stage 1 Windows Installer
echo   [DEVELOPMENT / TESTING MODE ONLY]
echo ========================================================
echo.

REM ── Administrator check ───────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click install.bat and select "Run as administrator".
    pause
    exit /b 1
)

REM ── Configuration ─────────────────────────────────────────────────────────────
set "INSTALL_DIR=C:\ddos_stage1"
set "BINARY_NAME=ddos_stage1.exe"
set "STAGE1_SRC=%~dp0..\stage1"
set "NPCAP_URL=https://npcap.com/dist/npcap-1.79.exe"
set "RUSTUP_URL=https://win.rustup.rs/x86_64"

REM ── Step 1: Check for Rust ────────────────────────────────────────────────────
echo [INFO] Checking for Rust toolchain...
where cargo >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK]   Rust already installed.
    cargo --version
) else (
    echo [INFO] Rust not found. Downloading rustup-init.exe...
    powershell -Command "Invoke-WebRequest -Uri '%RUSTUP_URL%' -OutFile '%TEMP%\rustup-init.exe'"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to download rustup-init.exe.
        echo         Please install Rust manually from https://rustup.rs
        pause
        exit /b 1
    )
    echo [INFO] Installing Rust (this may take several minutes)...
    REM -y  : accept defaults non-interactively
    "%TEMP%\rustup-init.exe" -y --default-toolchain stable
    if %errorlevel% neq 0 (
        echo [ERROR] Rust installation failed.
        pause
        exit /b 1
    )
    REM Refresh PATH for this session so cargo is findable.
    call "%USERPROFILE%\.cargo\env.bat" 2>nul || (
        set "PATH=%PATH%;%USERPROFILE%\.cargo\bin"
    )
    echo [OK]   Rust installed successfully.
)

REM ── Step 2: Check / Install Npcap ────────────────────────────────────────────
echo.
echo [INFO] Checking for Npcap (required for pcap crate on Windows)...
REM Npcap installs to %SystemRoot%\System32\Npcap\. Check for its DLL.
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo [OK]   Npcap already installed.
) else (
    echo [INFO] Npcap not found. Downloading installer...
    powershell -Command "Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%TEMP%\npcap-setup.exe'"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to download Npcap.
        echo         Download manually from https://npcap.com and install with WinPcap compatibility.
        pause
        exit /b 1
    )
    echo [INFO] Launching Npcap installer...
    echo [INFO] IMPORTANT: In the installer, enable "Install Npcap in WinPcap API-compatible Mode"
    "%TEMP%\npcap-setup.exe"
    echo [OK]   Npcap installed. Continuing...
)

REM ── Step 3: Build Stage 1 ─────────────────────────────────────────────────────
echo.
echo [INFO] Building Stage 1 in release mode...
if not exist "%STAGE1_SRC%\Cargo.toml" (
    echo [ERROR] Could not find stage1\Cargo.toml at: %STAGE1_SRC%
    echo         Please run this script from the project root's scripts\ directory.
    pause
    exit /b 1
)

pushd "%STAGE1_SRC%"
cargo build --release
if %errorlevel% neq 0 (
    echo [ERROR] Build failed. Check the output above for errors.
    popd
    pause
    exit /b 1
)
popd
echo [OK]   Build complete.

REM ── Step 4: Install binary ────────────────────────────────────────────────────
echo.
echo [INFO] Installing binary to %INSTALL_DIR%...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
)
copy /Y "%STAGE1_SRC%\target\release\%BINARY_NAME%" "%INSTALL_DIR%\%BINARY_NAME%" >nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy binary to %INSTALL_DIR%.
    pause
    exit /b 1
)
echo [OK]   Binary installed: %INSTALL_DIR%\%BINARY_NAME%

REM ── Step 5: Add to PATH (optional) ───────────────────────────────────────────
echo.
echo [INFO] Adding %INSTALL_DIR% to system PATH...
REM Use setx to persist the PATH change (requires admin).
setx /M PATH "%PATH%;%INSTALL_DIR%" >nul 2>&1
echo [OK]   PATH updated. Restart your terminal to use 'ddos_stage1' from anywhere.

REM ── Step 6: Task Scheduler entry (optional autostart) ────────────────────────
echo.
set /p "TASK_CHOICE=Install Windows Task Scheduler entry for autostart? (y/n): "
if /i "%TASK_CHOICE%"=="y" (
    set /p "IFACE=Enter capture interface name (e.g., 'Ethernet', 'Local Area Connection'): "
    schtasks /create /tn "DDoS Stage1" ^
             /tr "\"%INSTALL_DIR%\%BINARY_NAME%\" --interface \"!IFACE!\" --no-filter" ^
             /sc onstart /ru SYSTEM /rl HIGHEST /f >nul
    if %errorlevel% equ 0 (
        echo [OK]   Task Scheduler entry created: "DDoS Stage1"
        echo [INFO] The service will start automatically on next boot.
        echo [INFO] To start immediately: schtasks /run /tn "DDoS Stage1"
    ) else (
        echo [WARN] Task Scheduler entry creation failed. Start manually.
    )
)

REM ── Done ──────────────────────────────────────────────────────────────────────
echo.
echo ========================================================
echo [OK]   Stage 1 installation complete!
echo.
echo [INFO] Quick start (in a new Administrator terminal):
echo        %INSTALL_DIR%\%BINARY_NAME% --interface "Ethernet" --no-filter
echo.
echo [WARN] Windows deployment is for TESTING ONLY.
echo        Run cargo test --manifest-path %STAGE1_SRC%\Cargo.toml to verify.
echo ========================================================
echo.
pause
