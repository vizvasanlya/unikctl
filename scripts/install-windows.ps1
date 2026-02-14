Param(
    [string]$Version = "",
    [string]$InstallDir = "$env:USERPROFILE\\bin",
    [string]$Repo = "vizvasanlya/unikctl"
)

$ErrorActionPreference = "Stop"

function Get-Arch {
    if ($env:PROCESSOR_ARCHITECTURE -match "ARM64") { return "arm64" }
    return "amd64"
}

function Get-LatestVersion([string]$Repository) {
    $api = "https://api.github.com/repos/$Repository/releases/latest"
    $res = Invoke-RestMethod -Uri $api -UseBasicParsing
    if (-not $res.tag_name) {
        throw "Could not determine latest release from $api"
    }
    return $res.tag_name
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestVersion -Repository $Repo
}

$ver = $Version.TrimStart("v")
$arch = Get-Arch

# Requires release artifact: unikctl_<version>_windows_<arch>.zip
$zipName = "unikctl_${ver}_windows_${arch}.zip"
$url = "https://github.com/$Repo/releases/download/$Version/$zipName"

$tmp = Join-Path $env:TEMP ("unikctl-" + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $zip = Join-Path $tmp $zipName
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    $exe = Join-Path $tmp "unikctl.exe"
    if (-not (Test-Path $exe)) {
        throw "Release archive did not contain unikctl.exe"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $InstallDir "unikctl.exe") -Force

    Write-Host "Installed to $InstallDir\\unikctl.exe"
    Write-Host "If needed, add $InstallDir to PATH."
    Write-Host "Check: unikctl --version"
}
finally {
    if (Test-Path $tmp) {
        Remove-Item -Path $tmp -Recurse -Force
    }
}

