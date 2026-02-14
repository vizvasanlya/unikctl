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

    docker buildx imagetools create --tag $dst $src
    if ($LASTEXITCODE -ne 0) {
      throw "failed publishing $src -> $dst"
    }

    docker buildx imagetools inspect $dst *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "failed to verify $dst"
    }
  }
}

Write-Host "runtime image publish complete"
