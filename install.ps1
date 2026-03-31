#Requires -Version 5.0
param(
    [Parameter(Position = 0)]
    [string]$Action = "install",
    [Alias("p")]
    [switch]$ProxyFirst
)

$ErrorActionPreference = "Stop"

$Repo       = "ShadowPower/sshc-rs"
$Binary     = "sshc"
$Proxy      = "https://gh-proxy.org/"
$InstallDir = "$env:USERPROFILE\.sshc"

function Write-Info($m) { Write-Host "[INFO] $m" -ForegroundColor Blue }
function Write-Ok($m)   { Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err($m)  { Write-Host "[ERROR] $m" -ForegroundColor Red }

# ── Network ───────────────────────────────────────────────────────

function Get-CandidateUrls([string]$Url) {
    $proxyUrl = "${Proxy}${Url}"
    if ($ProxyFirst) { return @($proxyUrl, $Url) }
    return @($Url, $proxyUrl)
}

function Invoke-RestWithFallback([string]$Url) {
    foreach ($candidate in (Get-CandidateUrls $Url)) {
        try {
            return Invoke-RestMethod -Uri $candidate `
                -Headers @{ "User-Agent" = "sshc-installer" } -TimeoutSec 10
        } catch {
            continue
        }
    }
    return $null
}

function Invoke-DownloadWithFallback([string]$Url, [string]$OutFile) {
    foreach ($candidate in (Get-CandidateUrls $Url)) {
        try {
            Invoke-WebRequest -Uri $candidate -OutFile $OutFile -UseBasicParsing -TimeoutSec 15
            return $true
        } catch {
            continue
        }
    }
    return $false
}

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

function Get-ArchSuffix {
    $arch = $null

    try {
        $arch = [string]([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    } catch {
        $arch = $null
    }

    if ([string]::IsNullOrWhiteSpace($arch)) {
        $arch = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITEW6432")
    }
    if ([string]::IsNullOrWhiteSpace($arch)) {
        $arch = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    }

    $normalizedArch = if ([string]::IsNullOrWhiteSpace($arch)) { "" } else { $arch.Trim().ToUpperInvariant() }

    switch ($normalizedArch) {
        "X64"   { return "amd64" }
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Err "Unsupported architecture: '$arch'"; exit 1 }
    }
}

function Do-Install {
    $suffix = Get-ArchSuffix
    $asset = "sshc-windows-${suffix}.zip"

    Write-Info "Fetching latest release..."
    if ($ProxyFirst) { Write-Info "Proxy-first mode enabled." }
    $release = Invoke-RestWithFallback "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release) { Write-Err "Failed to reach GitHub API"; exit 1 }

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
        if (-not (Invoke-DownloadWithFallback $url $zip)) {
            Write-Err "Download failed"; exit 1
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
    "remove"    { Do-Uninstall }
    default     { Write-Err "Usage: .\install.ps1 [install|uninstall] [-p]"; exit 1 }
}
