Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
Mirrors runtime images into your unikctl registry namespace.

.DESCRIPTION
Defaults:
  SOURCE_PREFIX=unikraft.org
  TARGET_PREFIX=ghcr.io/vizvasanlya/unikctl
  IMAGES=base,nodejs,python,java,dotnet
  TAGS=latest

Requires:
  docker with buildx
  docker login ghcr.io

.EXAMPLE
  ./scripts/publish-runtimes.ps1

.EXAMPLE
  $env:TAGS="latest,v0.1.11"; ./scripts/publish-runtimes.ps1
#>

$sourcePrefix = if ($env:SOURCE_PREFIX) { $env:SOURCE_PREFIX } else { "unikraft.org" }
$targetPrefix = if ($env:TARGET_PREFIX) { $env:TARGET_PREFIX } else { "ghcr.io/vizvasanlya/unikctl" }
$imagesCsv = if ($env:IMAGES) { $env:IMAGES } else { "base,nodejs,python,java,dotnet" }
$tagsCsv = if ($env:TAGS) { $env:TAGS } else { "latest" }
$dryRun = if ($env:DRY_RUN) { $env:DRY_RUN } else { "false" }
$retries = if ($env:RETRIES) { [int]$env:RETRIES } else { 3 }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "required command not found: docker"
}

docker buildx version *> $null
if ($LASTEXITCODE -ne 0) {
  throw "docker buildx is required"
}

Write-Host "runtime publish config:"
Write-Host "  source: $sourcePrefix"
Write-Host "  target: $targetPrefix"
Write-Host "  images: $imagesCsv"
Write-Host "  tags:   $tagsCsv"
Write-Host "  retries:$retries"

$images = $imagesCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
$tags = $tagsCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

foreach ($image in $images) {
  foreach ($tag in $tags) {
    $src = "$sourcePrefix/$image`:$tag"
    $dst = "$targetPrefix/$image`:$tag"

    Write-Host "publishing $src -> $dst"
    if ($dryRun -eq "true") {
      Write-Host "[dry-run] docker buildx imagetools create --tag $dst $src"
      Write-Host "[dry-run] docker buildx imagetools inspect $dst"
      continue
    }

    $published = $false
    for ($attempt = 1; $attempt -le $retries; $attempt++) {
      docker buildx imagetools create --tag $dst $src
      if ($LASTEXITCODE -eq 0) {
        $published = $true
        break
      }
      Start-Sleep -Seconds 2
    }
    if (-not $published) {
      throw "failed publishing $src -> $dst after $retries attempts"
    }

    $verified = $false
    for ($attempt = 1; $attempt -le $retries; $attempt++) {
      docker buildx imagetools inspect $dst *> $null
      if ($LASTEXITCODE -eq 0) {
        $verified = $true
        break
      }
      Start-Sleep -Seconds 2
    }
    if (-not $verified) {
      throw "failed to verify $dst after $retries attempts"
    }
  }
}

Write-Host "runtime image publish complete"
