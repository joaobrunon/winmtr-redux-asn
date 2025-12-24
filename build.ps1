#!/usr/bin/env pwsh
#Requires -Version 5.1

<#
.SYNOPSIS
    Build script for WinMTR Redux

.DESCRIPTION
    Configures and builds WinMTR using CMake and Visual Studio 2022.
    Supports multiple configurations and build options.

.PARAMETER Config
    Build configuration: Debug or Release (default: Release)

.PARAMETER Arch
    Target architecture: x64 or x86 (default: x64)

.PARAMETER Clean
    Clean build directory before building

.PARAMETER BuildOnly
    Skip CMake configuration and only build

.PARAMETER Install
    Install after building

.PARAMETER Package
    Create a zip package with the built executable

.EXAMPLE
    .\build.ps1
    Build x64 Release configuration

.EXAMPLE
    .\build.ps1 -Config Debug -Arch x64
    Build x64 Debug configuration

.EXAMPLE
    .\build.ps1 -Clean
    Clean and build x64 Release

.EXAMPLE
    .\build.ps1 -BuildOnly
    Build without reconfiguring CMake
#>

param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Release',

    [ValidateSet('x64', 'x86')]
    [string]$Arch = 'x64',

    [switch]$Clean,
    [switch]$BuildOnly,
    [switch]$Install,
    [switch]$Package
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# Configuration
# ============================================================================
$ScriptDir = $PSScriptRoot
$BuildDir = Join-Path $ScriptDir "build"
$PresetName = "$Arch-$($Config.ToLower())"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "WinMTR Redux - Build Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Configuration: $Config" -ForegroundColor Yellow
Write-Host "Architecture:  $Arch" -ForegroundColor Yellow
Write-Host "Preset:        $PresetName" -ForegroundColor Yellow
Write-Host "============================================`n" -ForegroundColor Cyan

# ============================================================================
# Check Prerequisites
# ============================================================================
Write-Host "[1/4] Checking prerequisites..." -ForegroundColor Green

# Check for CMake
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Error "CMake not found! Please install CMake 3.20 or later."
    exit 1
}

$cmakeVersion = cmake --version | Select-String -Pattern "(\d+\.\d+\.\d+)"  | ForEach-Object { $_.Matches.Groups[1].Value }
Write-Host "  ✓ CMake $cmakeVersion found" -ForegroundColor Gray

# Check for Visual Studio
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "Visual Studio not found! Please install Visual Studio 2022."
    exit 1
}

$vsPath = & $vswhere -latest -property installationPath
if (-not $vsPath) {
    Write-Error "Visual Studio 2022 not found!"
    exit 1
}

Write-Host "  ✓ Visual Studio found at: $vsPath" -ForegroundColor Gray

# ============================================================================
# Clean
# ============================================================================
if ($Clean) {
    Write-Host "`n[2/4] Cleaning build directory..." -ForegroundColor Green
    if (Test-Path $BuildDir) {
        Remove-Item -Path $BuildDir -Recurse -Force
        Write-Host "  ✓ Build directory cleaned" -ForegroundColor Gray
    }
} else {
    Write-Host "`n[2/4] Skipping clean (use -Clean to clean)" -ForegroundColor Green
}

# ============================================================================
# Configure
# ============================================================================
if (-not $BuildOnly) {
    Write-Host "`n[3/4] Configuring with CMake..." -ForegroundColor Green

    $cmakeArgs = @(
        '--preset', $PresetName
    )

    Write-Host "  Running: cmake $($cmakeArgs -join ' ')" -ForegroundColor Gray
    & cmake @cmakeArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configuration failed!"
        exit $LASTEXITCODE
    }

    Write-Host "  ✓ Configuration completed" -ForegroundColor Gray
} else {
    Write-Host "`n[3/4] Skipping configuration (use without -BuildOnly to reconfigure)" -ForegroundColor Green
}

# ============================================================================
# Build
# ============================================================================
Write-Host "`n[4/4] Building..." -ForegroundColor Green

$buildArgs = @(
    '--build', "out/build/$PresetName"
    '--config', $Config
    '--', '/m'  # MSBuild parallel build
)

Write-Host "  Running: cmake $($buildArgs -join ' ')" -ForegroundColor Gray
& cmake @buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed!"
    exit $LASTEXITCODE
}

Write-Host "  ✓ Build completed" -ForegroundColor Gray

# ============================================================================
# Install (optional)
# ============================================================================
if ($Install) {
    Write-Host "`n[5/5] Installing..." -ForegroundColor Green

    $installArgs = @(
        '--install', "out/build/$PresetName"
        '--config', $Config
    )

    & cmake @installArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Installation failed!"
        exit $LASTEXITCODE
    }

    Write-Host "  ✓ Installation completed" -ForegroundColor Gray
}

# ============================================================================
# Package (optional)
# ============================================================================
if ($Package) {
    Write-Host "`n[6/6] Packaging..." -ForegroundColor Green

    $exePath = "out\build\$PresetName\bin\$Config\WinMTR.exe"
    if (-not (Test-Path $exePath)) {
        Write-Error "Executable not found at expected location: $exePath"
        exit 1
    }

    $distDir = Join-Path $ScriptDir "dist"
    if (-not (Test-Path $distDir)) {
        New-Item -ItemType Directory -Path $distDir | Out-Null
    }

    $zipName = "WinMTR-$PresetName-$Config.zip"
    $zipPath = Join-Path $distDir $zipName

    if (Test-Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }

    Compress-Archive -Path $exePath -DestinationPath $zipPath
    Write-Host "  ✓ Package created: $zipPath" -ForegroundColor Gray
}

# ============================================================================
# Summary
# ============================================================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Build Successful! " -ForegroundColor Green -NoNewline
Write-Host "🎉" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan

$exePath = "out\build\$PresetName\bin\$Config\WinMTR.exe"
if (Test-Path $exePath) {
    Write-Host "Executable: $exePath" -ForegroundColor Yellow
    $fileSize = (Get-Item $exePath).Length / 1KB
    Write-Host "Size:       $([math]::Round($fileSize, 2)) KB" -ForegroundColor Yellow
} else {
    Write-Host "Executable: Not found at expected location" -ForegroundColor Red
}

Write-Host "============================================`n" -ForegroundColor Cyan

# ============================================================================
# Instructions
# ============================================================================
Write-Host "To run the application:" -ForegroundColor White
Write-Host "  $exePath`n" -ForegroundColor Gray

exit 0
