param(
  [string]$Version = "0.1.0",
  [switch]$InstallGo
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Dist = Join-Path $Root "dist"
$Pkg = "./cmd/sslcertcheck"

function ConvertTo-NormalizedVersion {
  param([string]$Value)

  if ($Value -notmatch '^(\d+)\.(\d+)(?:\.(\d+))?') {
    throw "Unable to parse version '$Value'."
  }

  $patch = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
  return [version]::new([int]$Matches[1], [int]$Matches[2], $patch)
}

function Get-RequiredGoVersion {
  $goMod = Join-Path $Root "go.mod"

  foreach ($line in Get-Content -Path $goMod) {
    if ($line -match '^\s*go\s+([0-9]+(?:\.[0-9]+){1,2})\s*$') {
      return $Matches[1]
    }
  }

  throw "Unable to find the required Go version in go.mod."
}

function Get-InstalledGoVersion {
  $go = Get-Command go -ErrorAction SilentlyContinue

  if (-not $go) {
    $defaultGo = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path -Path $defaultGo) {
      $env:PATH = "C:\Program Files\Go\bin;$env:PATH"
      $go = Get-Command go -ErrorAction SilentlyContinue
    }
  }

  if (-not $go) {
    return $null
  }

  $output = & go version
  if ($output -notmatch 'go([0-9]+\.[0-9]+(?:\.[0-9]+)?)') {
    throw "Unable to parse installed Go version from: $output"
  }

  return @{
    Raw = $output
    Version = $Matches[1]
  }
}

function Show-GoSetupHelp {
  param([string]$RequiredGoVersion)

  Write-Host ""
  Write-Host "Go $RequiredGoVersion or newer is required, but Go was not found on PATH." -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Install options:"
  Write-Host "  1. Assisted Windows install: .\scripts\build.ps1 -InstallGo"
  Write-Host "  2. Manual installer:         https://go.dev/dl/"
  Write-Host "  3. Docker fallback:          docker build -t sslcertcheck:local ."
  Write-Host ""
  Write-Host "After installing Go, reopen PowerShell so PATH changes are available."
}

function Install-Go {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) {
    throw "winget was not found. Install Go manually from https://go.dev/dl/ and reopen PowerShell."
  }

  Write-Host "Installing Go with winget..."
  winget install --id GoLang.Go --exact --source winget --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) {
    throw "winget failed to install Go. Install Go manually from https://go.dev/dl/ and reopen PowerShell."
  }
}

function Upgrade-Go {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) {
    throw "winget was not found. Update Go manually from https://go.dev/dl/ and reopen PowerShell."
  }

  Write-Host "Updating Go with winget..."
  winget upgrade --id GoLang.Go --exact --source winget --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) {
    throw "winget failed to update Go. Update Go manually from https://go.dev/dl/ and reopen PowerShell."
  }
}

function Assert-GoAvailable {
  $requiredText = Get-RequiredGoVersion
  $required = ConvertTo-NormalizedVersion $requiredText
  $installed = Get-InstalledGoVersion

  if (-not $installed) {
    if ($InstallGo) {
      Install-Go
      $installed = Get-InstalledGoVersion
    } else {
      Show-GoSetupHelp $requiredText
      exit 1
    }
  }

  if (-not $installed) {
    throw "Go was installed, but it is not available in this PowerShell session. Reopen PowerShell and run the script again."
  }

  $installedVersion = ConvertTo-NormalizedVersion $installed.Version
  if ($installedVersion -lt $required) {
    if ($InstallGo) {
      Upgrade-Go
      $installed = Get-InstalledGoVersion
      if (-not $installed) {
        throw "Go was updated, but it is not available in this PowerShell session. Reopen PowerShell and run the script again."
      }
      $installedVersion = ConvertTo-NormalizedVersion $installed.Version
    }
  }

  if ($installedVersion -lt $required) {
    Write-Host ""
    Write-Host "Go $($installed.Version) is installed, but this project requires Go $requiredText or newer." -ForegroundColor Yellow
    Write-Host "Update Go manually from https://go.dev/dl/ or run: .\scripts\build.ps1 -InstallGo"
    exit 1
  }

  Write-Host "Using $($installed.Raw)"
}

Assert-GoAvailable
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Push-Location $Root
try {
  go test ./...

  $targets = @(
    @{ GOOS="windows"; GOARCH="amd64"; EXT=".exe" },
    @{ GOOS="windows"; GOARCH="arm64"; EXT=".exe" },
    @{ GOOS="linux";   GOARCH="amd64"; EXT="" },
    @{ GOOS="linux";   GOARCH="arm64"; EXT="" },
    @{ GOOS="darwin";  GOARCH="amd64"; EXT="" },
    @{ GOOS="darwin";  GOARCH="arm64"; EXT="" },
    @{ GOOS="freebsd"; GOARCH="amd64"; EXT="" },
    @{ GOOS="solaris"; GOARCH="amd64"; EXT="" }
  )

  foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $env:CGO_ENABLED = "0"
    $out = Join-Path $Dist ("sslcertcheck-{0}-{1}{2}" -f $t.GOOS, $t.GOARCH, $t.EXT)
    Write-Host "building $out"
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $out $Pkg
  }
} finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
  Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}
