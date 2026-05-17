param(
  [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Dist = Join-Path $Root "dist"
$Pkg = "./cmd/sslcertcheck"

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
