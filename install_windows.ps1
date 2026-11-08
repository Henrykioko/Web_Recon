# WebRecon Windows Setup Installer
# Supported: Windows 10 / Windows 11
#
# Run from project root:
# Set-ExecutionPolicy -Scope Process Bypass
# .\install_windows.ps1

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

$VenvPath = Join-Path $ProjectRoot "venv"
$ToolDir = Join-Path $env:LOCALAPPDATA "WebRecon\bin"
$WhatWebDir = Join-Path $env:LOCALAPPDATA "WebRecon\WhatWeb"

# ------------------------------------------
# Helper functions
# ------------------------------------------

function Write-Step {
    param([string]$Message)

    Write-Host "`n====================================" -ForegroundColor DarkGray
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor DarkGray
}

function Test-Command {
    param([string]$Name)

    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-Path {
    $MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")

    $env:Path = "$MachinePath;$UserPath;$ToolDir"
}

function Add-UserPath {
    param([string]$NewPath)

    if (-not (Test-Path $NewPath)) {
        return
    }

    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $Entries = @($CurrentPath -split ";" | Where-Object { $_ })

    if ($Entries -notcontains $NewPath) {
        $UpdatedPath = ($Entries + $NewPath) -join ";"

        [Environment]::SetEnvironmentVariable(
            "Path",
            $UpdatedPath,
            "User"
        )
    }

    Refresh-Path
}

function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$Name
    )

    if (-not (Test-Command "winget")) {
        Write-Warning "winget is unavailable. Cannot automatically install $Name."
        return
    }

    Write-Host "Installing $Name..." -ForegroundColor Yellow

    winget install `
        --id $PackageId `
        --exact `
        --silent `
        --accept-package-agreements `
        --accept-source-agreements

    Refresh-Path

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$Name installation returned exit code $LASTEXITCODE."
    }
}

# ------------------------------------------
# 1. Check project files
# ------------------------------------------

Write-Step "Checking project files"

if (-not (Test-Path ".\app.py")) {
    throw "app.py was not found. Run this installer from the WebRecon project root."
}

if (-not (Test-Path ".\requirements.txt")) {
    throw "requirements.txt was not found."
}

# ------------------------------------------
# 2. Check Python
# ------------------------------------------

Write-Step "Checking Python"

if ((-not (Test-Command "py")) -and (-not (Test-Command "python"))) {
    throw "Python is missing. Install Python 3.11 or later from https://www.python.org/downloads/windows/"
}

$PythonCommand = if (Test-Command "py") {
    "py"
}
else {
    "python"
}

if ($PythonCommand -eq "py") {
    py -3 --version

    if ($LASTEXITCODE -ne 0) {
        throw "Python 3 could not be started using the Python launcher."
    }
}
else {
    python --version

    if ($LASTEXITCODE -ne 0) {
        throw "Python could not be started."
    }
}

# ------------------------------------------
# 3. Create virtual environment
# ------------------------------------------

Write-Step "Creating Python virtual environment"

if (-not (Test-Path $VenvPath)) {

    if ($PythonCommand -eq "py") {
        py -3 -m venv $VenvPath
    }
    else {
        python -m venv $VenvPath
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment."
    }
}
else {
    Write-Host "[INFO] Existing venv detected. Reusing it." -ForegroundColor Yellow
}

$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment is invalid. Check the venv directory."
}

# ------------------------------------------
# 4. Install Python dependencies
# ------------------------------------------

Write-Step "Installing Python dependencies"

& $VenvPython -m pip install --upgrade pip setuptools wheel

if ($LASTEXITCODE -ne 0) {
    throw "Failed to upgrade pip."
}

& $VenvPython -m pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    throw "Failed to install requirements.txt."
}

& $VenvPython -m pip check

if ($LASTEXITCODE -ne 0) {
    throw "Python dependency conflicts were detected."
}

# ------------------------------------------
# 5. Prepare WebRecon tool directory
# ------------------------------------------

Write-Step "Preparing external tools directory"

New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null

Add-UserPath $ToolDir

# ------------------------------------------
# 6. Install Nmap
# ------------------------------------------

Write-Step "Installing Nmap"

if (-not (Test-Command "nmap")) {
    Install-WingetPackage "Insecure.Nmap" "Nmap"
}

# Check common Nmap installation directories
$NmapDirectories = @(
    "${env:ProgramFiles(x86)}\Nmap",
    "$env:ProgramFiles\Nmap"
)

foreach ($Directory in $NmapDirectories) {
    if (Test-Path (Join-Path $Directory "nmap.exe")) {
        Add-UserPath $Directory
    }
}

Refresh-Path

# ------------------------------------------
# 7. Install Ruby
# ------------------------------------------

Write-Step "Installing Ruby"

if (-not (Test-Command "ruby")) {
    Install-WingetPackage "RubyInstallerTeam.RubyWithDevKit.3.4" "Ruby with DevKit"
}

# Check common Ruby installation directories
$RubyDirectories = @(
    "$env:ProgramFiles\Ruby34-x64\bin",
    "$env:ProgramFiles\Ruby35-x64\bin",
    "C:\Ruby34-x64\bin",
    "C:\Ruby35-x64\bin"
)

foreach ($Directory in $RubyDirectories) {
    if (Test-Path (Join-Path $Directory "ruby.exe")) {
        Add-UserPath $Directory
    }
}

Refresh-Path

# ------------------------------------------
# 8. Install Git
# ------------------------------------------

Write-Step "Installing Git"

if (-not (Test-Command "git")) {
    Install-WingetPackage "Git.Git" "Git"
}

Refresh-Path

# ------------------------------------------
# 9. Install WHOIS
# ------------------------------------------

Write-Step "Installing WHOIS"

$WhoisPath = Join-Path $ToolDir "whois.exe"

if (-not (Test-Command "whois") -and -not (Test-Path $WhoisPath)) {

    try {
        Invoke-WebRequest `
            -Uri "https://live.sysinternals.com/whois.exe" `
            -OutFile $WhoisPath

        Write-Host "[OK] WHOIS downloaded." -ForegroundColor Green
    }
    catch {
        Write-Warning "WHOIS download failed: $($_.Exception.Message)"
    }
}

# ------------------------------------------
# 10. Install WhatWeb
# ------------------------------------------

Write-Step "Installing WhatWeb"

$WhatWebLauncher = Join-Path $ToolDir "whatweb.cmd"
$WhatWebScript = Join-Path $WhatWebDir "whatweb"

if (-not (Test-Command "whatweb") -and -not (Test-Path $WhatWebLauncher)) {

    if (-not (Test-Command "ruby")) {
        Write-Warning "Ruby is unavailable. WhatWeb cannot be installed."
    }
    elseif (-not (Test-Command "git")) {
        Write-Warning "Git is unavailable. WhatWeb cannot be downloaded."
    }
    else {

        if (-not (Test-Path $WhatWebDir)) {

            git clone --depth 1 `
                https://github.com/urbanadventurer/WhatWeb.git `
                $WhatWebDir

            if ($LASTEXITCODE -ne 0) {
                Write-Warning "WhatWeb download failed."
            }
        }

        if (Test-Path $WhatWebScript) {

            $LauncherContent = @"
@echo off
ruby "$WhatWebScript" %*
"@

            Set-Content `
                -Path $WhatWebLauncher `
                -Value $LauncherContent `
                -Encoding ASCII

            Write-Host "[OK] WhatWeb launcher created." -ForegroundColor Green
        }
        else {
            Write-Warning "WhatWeb executable was not found."
        }
    }
}

Add-UserPath $ToolDir
Refresh-Path

# ------------------------------------------
# 11. Install Go
# ------------------------------------------

Write-Step "Installing Go"

if (-not (Test-Command "go")) {
    Install-WingetPackage "GoLang.Go" "Go"
}

$GoBin = Join-Path $env:USERPROFILE "go\bin"

if (Test-Path $GoBin) {
    Add-UserPath $GoBin
}

Refresh-Path

# ------------------------------------------
# 12. Install Gobuster
# ------------------------------------------

Write-Step "Installing Gobuster"

if (-not (Test-Command "gobuster")) {

    if (Test-Command "go") {

        go install github.com/OJ/gobuster/v3@latest

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Gobuster installation failed."
        }
    }
    else {
        Write-Warning "Go is unavailable. Gobuster cannot be installed."
    }
}

if (Test-Path $GoBin) {
    Add-UserPath $GoBin
}

Refresh-Path

# ------------------------------------------
# 13. Verify external tools
# ------------------------------------------

Write-Step "Verifying external scanning tools"

$Tools = @("nmap", "whatweb", "whois", "gobuster")

$MissingTools = @()

foreach ($Tool in $Tools) {

    $Found = Get-Command $Tool -ErrorAction SilentlyContinue

    if ($Found) {
        Write-Host "[OK] $Tool : $($Found.Source)" -ForegroundColor Green
    }
    else {
        Write-Host "[MISSING] $Tool" -ForegroundColor Red
        $MissingTools += $Tool
    }
}

# ------------------------------------------
# 14. Verify Python dependencies
# ------------------------------------------

Write-Step "Verifying Python dependencies"

& $VenvPython -c "import flask, flask_sqlalchemy, requests, dateutil; print('All required Python imports successful.')"

if ($LASTEXITCODE -ne 0) {
    throw "Python dependency verification failed."
}

# ------------------------------------------
# 15. Test tool execution
# ------------------------------------------

Write-Step "Testing scanning tools"

$ToolTests = @{
    "nmap" = @("--version")
    "whatweb" = @("--version")
    "gobuster" = @("version")
}

foreach ($Tool in $ToolTests.Keys) {

    if (Test-Command $Tool) {

        Write-Host "`nTesting $Tool..." -ForegroundColor Cyan

        & $Tool @($ToolTests[$Tool]) 2>&1 | Select-Object -First 3

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "$Tool was found but its version test returned an error."
        }
    }
}

# ------------------------------------------
# 16. Final result
# ------------------------------------------

Write-Step "WebRecon setup results"

if ($MissingTools.Count -eq 0) {

    Write-Host "WEBRECON SETUP COMPLETED SUCCESSFULLY" -ForegroundColor Green
}
else {

    Write-Host "SETUP COMPLETED WITH MISSING TOOLS" -ForegroundColor Red

    Write-Host "`nMissing tools:" -ForegroundColor Yellow

    foreach ($Tool in $MissingTools) {
        Write-Host "- $Tool"
    }
}

Write-Host "`nActivate your virtual environment:" -ForegroundColor Green
Write-Host ".\venv\Scripts\Activate.ps1"

Write-Host "`nVerify your installation:" -ForegroundColor Green
Write-Host "python -m pip check"

Write-Host "`nStart WebRecon:" -ForegroundColor Green
Write-Host "python app.py"

if ($MissingTools.Count -gt 0) {
    exit 1
}