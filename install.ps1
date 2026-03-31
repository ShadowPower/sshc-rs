#Requires -Version 5.0
param([string]$Action = "install")

$ErrorActionPreference = "Stop"

$Repo       = "ShadowPower/sshc-rs"
$Binary     = "sshc"
$Proxy      = "https://gh-proxy.org/"
$InstallDir = "$env:USERPROFILE\.sshc"

function Write-Info($m) { Write-Host "[INFO] $m" -ForegroundColor Blue }
function Write-Ok($m)   { Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err($m)  { Write-Host "[ERROR] $m" -ForegroundColor Red }

# ── PATH (exact match) ───────────────────────────────────────────

function Add-ToPath($dir) {
    $parts = [Environment]::GetEnvironmentVariable("Path", "User") -split ";"
    if ($parts -contains $dir) { return }
    Write-Info "Adding $dir to user PATH"
    [Environment]::SetEnvironmentVariable("Path", "$($parts -join ';');$dir", "User")
    $env:Path += ";$dir"
}

function Remove-FromPath($dir) {
    $parts = [Environment]::GetEnvironmentVariable("Path", "User") -split ";"
    if ($parts -notcontains $dir) { return }
    $filtered = $parts | Where-Object { $_ -and $_ -ne $dir }
    [Environment]::SetEnvironmentVariable("Path", ($filtered -join ";"), "User")
    Write-Info "Removed $dir from user PATH"
}

# ── Install ───────────────────────────────────────────────────────

function Do-Install {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    $suffix = switch ($arch) {
        "X64"   { "amd64" }
        "Arm64" { "arm64" }
        default { Write-Err "Unsupported: $arch"; exit 1 }
    }
    $asset = "sshc-windows-${suffix}.zip"

    Write-Info "Fetching latest release..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
        -Headers @{ "User-Agent" = "sshc-installer" } -TimeoutSec 10

    $version = $release.tag_name
    $assetObj = $release.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
    if (-not $assetObj) { Write-Err "Asset $asset not found"; exit 1 }

    $url = $assetObj.browser_download_url
    Write-Info "Latest version: $version"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) "sshc-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $zip = Join-Path $tmp $asset
        Write-Info "Downloading $asset..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 15
        } catch {
            Write-Warn "Retrying via proxy..."
            Invoke-WebRequest -Uri "${Proxy}${url}" -OutFile $zip -UseBasicParsing -TimeoutSec 15
        }

        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        Copy-Item (Join-Path $tmp "$Binary.exe") (Join-Path $InstallDir "$Binary.exe") -Force
        Add-ToPath $InstallDir

        $cmd = Get-Command $Binary -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Ok (& $cmd.Source --version)
        } else {
            Write-Ok "Installed to $InstallDir\$Binary.exe"
            Write-Warn "Restart your terminal to use sshc."
        }
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ── Uninstall ─────────────────────────────────────────────────────

function Do-Uninstall {
    $exe = Join-Path $InstallDir "$Binary.exe"
    if (Test-Path $exe) {
        Remove-Item $exe -Force
        # remove dir if empty
        if (-not (Get-ChildItem $InstallDir -ErrorAction SilentlyContinue)) {
            Remove-Item $InstallDir -Force -ErrorAction SilentlyContinue
        }
        Remove-FromPath $InstallDir
        Write-Ok "Uninstalled."
    } else {
        Write-Warn "sshc is not installed."
    }
}

# ── Main ──────────────────────────────────────────────────────────

switch ($Action) {
    "install"   { Do-Install }
    "uninstall" { Do-Uninstall }
    default     { Write-Err "Usage: .\install.ps1 [install|uninstall]"; exit 1 }
}
