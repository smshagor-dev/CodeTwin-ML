param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ValidSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signature is not valid for $Path (status: $($signature.Status))"
    }
}

function Get-CodeTwinUninstallEntry {
    $roots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem $root -ErrorAction SilentlyContinue) {
            $entry = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $entry -and [string]$entry.DisplayName -eq "CodeTwin ML") {
                return $entry
            }
        }
    }
    return $null
}

function Get-CommandExecutable {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $trimmed = $Command.Trim()
    if ($trimmed -match '^"([^"]+)"') {
        return $Matches[1]
    }
    return ($trimmed -split '\s+')[0]
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$fixture = Join-Path $repo "fixtures\typescript-basic"
if (-not (Test-Path -LiteralPath $fixture -PathType Container)) {
    throw "Release smoke fixture is missing: $fixture"
}

$datasetState = Join-Path $env:LOCALAPPDATA "CodeTwinML\datasets\openmindai-dataset-install-state.json"
if (Test-Path -LiteralPath $datasetState) {
    throw "Release smoke runner is not clean: optional dataset state already exists at $datasetState"
}

Assert-ValidSignature -Path $installer

$uninstaller = $null
$appExe = $null
$smokeRoot = Join-Path ([IO.Path]::GetTempPath()) ("codetwin-release-smoke-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $smokeRoot | Out-Null

try {
    $install = Start-Process -FilePath $installer -ArgumentList "/S" -Wait -PassThru
    if ($install.ExitCode -ne 0) {
        throw "Silent NSIS installation failed with exit code $($install.ExitCode)"
    }
    if (Test-Path -LiteralPath $datasetState) {
        throw "Silent base installation unexpectedly installed or accepted optional dataset terms"
    }

    $entry = $null
    for ($attempt = 0; $attempt -lt 10 -and $null -eq $entry; $attempt++) {
        $entry = Get-CodeTwinUninstallEntry
        if ($null -eq $entry) { Start-Sleep -Milliseconds 500 }
    }
    if ($null -eq $entry) {
        throw "Installed CodeTwin ML uninstall registration was not found"
    }

    $uninstaller = Get-CommandExecutable -Command ([string]$entry.UninstallString)
    if ([string]::IsNullOrWhiteSpace($uninstaller) -or -not (Test-Path -LiteralPath $uninstaller)) {
        throw "Installed CodeTwin ML uninstaller could not be resolved"
    }
    $installRoot = Split-Path -Parent $uninstaller

    if (-not [string]::IsNullOrWhiteSpace([string]$entry.DisplayIcon)) {
        $iconExecutable = ([string]$entry.DisplayIcon).Trim()
        $iconExecutable = $iconExecutable -replace ',\s*-?\d+$', ''
        $iconExecutable = $iconExecutable.Trim('"')
        if (Test-Path -LiteralPath $iconExecutable -PathType Leaf) {
            $appExe = $iconExecutable
        }
    }
    if ($null -eq $appExe) {
        $candidates = Get-ChildItem -LiteralPath $installRoot -Filter "*.exe" -File -ErrorAction Stop |
            Where-Object { $_.FullName -ne $uninstaller -and $_.Name -notmatch '^uninstall' }
        if (@($candidates).Count -ne 1) {
            throw "Expected exactly one installed application executable; found $(@($candidates).Count)"
        }
        $appExe = $candidates[0].FullName
    }

    Assert-ValidSignature -Path $appExe

    $databasePath = Join-Path $smokeRoot "codetwin-release-smoke.sqlite3"
    & $appExe --release-smoke $fixture $databasePath
    if ($LASTEXITCODE -ne 0) {
        throw "Installed release smoke mode failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
        throw "Installed release smoke mode did not create its SQLite database"
    }
    if ((Get-Item -LiteralPath $databasePath).Length -le 0) {
        throw "Installed release smoke SQLite database is empty"
    }

    $gui = Start-Process -FilePath $appExe -PassThru
    Start-Sleep -Seconds 8
    if ($gui.HasExited) {
        throw "Installed desktop app exited during GUI startup smoke (exit code $($gui.ExitCode))"
    }
    Stop-Process -Id $gui.Id -Force
    $gui.WaitForExit()

    Write-Host "CodeTwin ML signed clean-machine release smoke passed."
}
finally {
    if ($null -ne $uninstaller -and (Test-Path -LiteralPath $uninstaller)) {
        $remove = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
        if ($remove.ExitCode -ne 0) {
            Write-Warning "Silent uninstall returned exit code $($remove.ExitCode)"
        }
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $smokeRoot
}
