param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,
    [string]$ReleaseTag = "openmindai-datasets-v1.0.0",
    [string]$Repository = "smshagor-dev/CodeTwin-ML",
    [switch]$AcceptDatasetTerms
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $AcceptDatasetTerms) {
    throw "OpenMindAI Dataset terms must be accepted before installation."
}
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "Invalid release repository."
}
if ($ReleaseTag -notmatch '^openmindai-datasets-v[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Invalid OpenMindAI Dataset release tag."
}

$manifestName = "openmindai-dataset-manifest-v1.0.0.json"
$releaseBase = "https://github.com/$Repository/releases/download/$ReleaseTag"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("CodeTwinML-openmindai-datasets-" + [Guid]::NewGuid().ToString("N"))
$downloadRoot = Join-Path $tempRoot "downloads"
$stagingRoot = Join-Path $tempRoot "staging"
$backupRoot = Join-Path $tempRoot "backup"
New-Item -ItemType Directory -Force -Path $downloadRoot, $stagingRoot, $backupRoot | Out-Null
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

function Get-RemoteFile {
    param([string]$Uri, [string]$Destination)
    $attempt = 0
    while ($attempt -lt 3) {
        $attempt++
        try {
            Write-Host "Downloading $Uri (attempt $attempt/3)"
            Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing -Headers @{
                "User-Agent" = "CodeTwin-ML-Installer/0.1"
                "Accept" = "application/octet-stream"
            } -TimeoutSec 300
            return
        }
        catch {
            Remove-Item -Force -ErrorAction SilentlyContinue $Destination
            if ($attempt -ge 3) { throw }
            Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
        }
    }
}

function Assert-SafeAssetName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or
        $Name -notmatch '^openmindai-dataset-[A-Za-z0-9._-]+\.(zip|json|txt)$' -or
        $Name.Contains('..') -or $Name.Contains('/') -or $Name.Contains('\')) {
        throw "Unsafe OpenMindAI Dataset asset name: $Name"
    }
}

try {
    $manifestPath = Join-Path $downloadRoot $manifestName
    Get-RemoteFile "$releaseBase/$manifestName" $manifestPath
    $manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json

    if ($manifest.schema_version -ne 1 -or $manifest.brand -ne "OpenMindAI Dataset") {
        throw "Unsupported OpenMindAI Dataset release manifest."
    }
    if ($manifest.release_tag -ne $ReleaseTag) {
        throw "Release manifest tag mismatch."
    }
    if ($null -eq $manifest.assets -or @($manifest.assets).Count -ne 4) {
        throw "OpenMindAI Dataset release must contain exactly four dataset assets."
    }

    foreach ($asset in $manifest.assets) {
        $assetName = [string]$asset.asset_name
        $datasetId = [string]$asset.dataset_id
        Assert-SafeAssetName $assetName
        if ($datasetId -notmatch '^[a-z0-9_]+$') {
            throw "Unsafe dataset id: $datasetId"
        }
        if (-not ([string]$asset.display_name).StartsWith("OpenMindAI Dataset")) {
            throw "Dataset branding mismatch for $datasetId"
        }

        $archivePath = Join-Path $downloadRoot $assetName
        Get-RemoteFile "$releaseBase/$assetName" $archivePath

        $actualSize = (Get-Item $archivePath).Length
        if ($actualSize -ne [Int64]$asset.size_bytes) {
            throw "Size mismatch for $assetName"
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
        if ($actualHash -ne ([string]$asset.sha256).ToLowerInvariant()) {
            throw "SHA-256 mismatch for $assetName"
        }

        $datasetStaging = Join-Path $stagingRoot $datasetId
        New-Item -ItemType Directory -Force -Path $datasetStaging | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $datasetStaging -Force
    }

    $replaced = @()
    try {
        foreach ($asset in $manifest.assets) {
            $datasetId = [string]$asset.dataset_id
            $target = Join-Path $InstallRoot $datasetId
            $staged = Join-Path $stagingRoot $datasetId
            $backup = Join-Path $backupRoot $datasetId
            $hadPrevious = Test-Path $target
            if ($hadPrevious) {
                Move-Item -Force $target $backup
            }
            try {
                Move-Item -Force $staged $target
            }
            catch {
                if ($hadPrevious -and (Test-Path $backup) -and -not (Test-Path $target)) {
                    Move-Item -Force $backup $target
                }
                throw
            }
            $replaced += $datasetId
        }
    }
    catch {
        foreach ($datasetId in $replaced) {
            $target = Join-Path $InstallRoot $datasetId
            $backup = Join-Path $backupRoot $datasetId
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $target
            if (Test-Path $backup) { Move-Item -Force $backup $target }
        }
        throw
    }

    $state = [ordered]@{
        schema_version = 1
        brand = "OpenMindAI Dataset"
        release_tag = $ReleaseTag
        installed_at_utc = [DateTime]::UtcNow.ToString("o")
        dataset_count = @($manifest.assets).Count
        dataset_terms_accepted = $true
        assets = @($manifest.assets | ForEach-Object {
            [ordered]@{
                dataset_id = $_.dataset_id
                display_name = $_.display_name
                asset_name = $_.asset_name
                sha256 = $_.sha256
            }
        })
    }
    $statePath = Join-Path $InstallRoot "openmindai-dataset-install-state.json"
    $state | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $statePath
    [Environment]::SetEnvironmentVariable("CODETWIN_DATASET_CACHE", $InstallRoot, "User")
    Write-Host "OpenMindAI Dataset installation complete: $InstallRoot"
    exit 0
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempRoot
}
