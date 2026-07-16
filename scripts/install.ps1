#Requires -Version 5.1
<#
.SYNOPSIS
ferrixd installer for Windows — install, update, or uninstall the prebuilt
ferrixd binary from GitHub releases (https://github.com/j-pfalzgraf/ferrixd).

.DESCRIPTION
One-liners (PowerShell):

  install:   irm https://raw.githubusercontent.com/j-pfalzgraf/ferrixd/main/scripts/install.ps1 | iex
  update:    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/j-pfalzgraf/ferrixd/main/scripts/install.ps1))) update
  uninstall: & ([scriptblock]::Create((irm https://raw.githubusercontent.com/j-pfalzgraf/ferrixd/main/scripts/install.ps1))) uninstall

Installs to %LOCALAPPDATA%\Programs\ferrixd (no admin rights needed) and adds
that directory to the user PATH. The download is verified against the
release's SHA-256 checksum before installation.

.PARAMETER Command
install (default), update, or uninstall.

.PARAMETER Version
A release tag like v0.1.0; default 'latest'.

.PARAMETER Dir
Install directory; default %LOCALAPPDATA%\Programs\ferrixd.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'update', 'uninstall')]
    [string]$Command = 'install',

    [Parameter(Position = 1)]
    [string]$Version = 'latest',

    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Programs\ferrixd')
)

$ErrorActionPreference = 'Stop'
$Repo = 'j-pfalzgraf/ferrixd'
$Asset = 'ferrixd-x86_64-pc-windows-msvc.zip'
$Exe = Join-Path $Dir 'ferrixd.exe'

function Get-UserPath { [string][Environment]::GetEnvironmentVariable('Path', 'User') }

function Add-DirToUserPath([string]$p) {
    $current = Get-UserPath
    if (($current -split ';') -notcontains $p) {
        [Environment]::SetEnvironmentVariable('Path', ("$current;$p".Trim(';')), 'User')
        $env:Path = "$env:Path;$p"
        Write-Host "added $p to your user PATH (new terminals pick it up automatically)"
    }
}

function Remove-DirFromUserPath([string]$p) {
    $parts = (Get-UserPath) -split ';' | Where-Object { $_ -and $_ -ne $p }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

if ($Command -eq 'uninstall') {
    if (-not (Test-Path $Dir)) {
        Write-Error "$Dir not found - nothing to uninstall"
    }
    Remove-Item -Recurse -Force $Dir
    Remove-DirFromUserPath $Dir
    Write-Host "uninstalled ferrixd from $Dir. Config files and databases were left untouched."
    return
}

if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    Write-Host 'note: no native Windows-ARM64 build yet - installing the x64 binary (runs via emulation on Windows 11).'
}

$old = $null
if (Test-Path $Exe) {
    try { $old = (& $Exe --version) } catch { $old = $null }
}
if ($Command -eq 'update' -and -not $old) {
    Write-Host 'no existing install found - performing a fresh install'
}

$base = if ($Version -eq 'latest') {
    "https://github.com/$Repo/releases/latest/download"
}
else {
    $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    "https://github.com/$Repo/releases/download/$tag"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ferrixd-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "downloading $base/$Asset ..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$Asset" -OutFile (Join-Path $tmp $Asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$Asset.sha256" -OutFile (Join-Path $tmp "$Asset.sha256")

    # The .sha256 file is a sha256sum-style line: "<hex>  <filename>".
    $want = ((Get-Content (Join-Path $tmp "$Asset.sha256") -Raw).Trim() -split '\s+')[0].ToLower()
    $got = (Get-FileHash (Join-Path $tmp $Asset) -Algorithm SHA256).Hash.ToLower()
    if (-not $want -or $want -ne $got) {
        throw "SHA-256 mismatch (expected '$want', got '$got') - refusing to install"
    }

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    try {
        Expand-Archive -Path (Join-Path $tmp $Asset) -DestinationPath $Dir -Force
    }
    catch {
        throw "could not write $Exe - if ferrixd is currently running, stop it and retry. ($_)"
    }

    Add-DirToUserPath $Dir
    $new = (& $Exe --version)
    if ($old) { Write-Host "updated: $old -> $new" }
    else { Write-Host "installed: $new -> $Exe" }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
