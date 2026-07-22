[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string] $Distro,

    [ValidateSet('Container', 'Artifact')]
    [string] $Mode = 'Container',

    [string] $ArtifactRoot,

    [string] $LockFile,

    [string[]] $Versions = @(
        '0.8.2', '0.9.0', '0.9.1', '0.9.2', '0.9.3', '0.9.4', '0.9.5'
    ),

    [ValidatePattern('^[A-Za-z0-9_./+-]+$')]
    [string] $PythonCommand = 'python3.14',

    [switch] $AllowImagePull,

    [string] $ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Versions = @($Versions)

if (-not $LockFile) {
    $LockFile = Join-Path $PSScriptRoot 'maddy-image-lock.json'
}

$Supported = @('0.8.2', '0.9.0', '0.9.1', '0.9.2', '0.9.3', '0.9.4', '0.9.5')
if ($Versions.Count -eq 0) {
    throw 'At least one version is required.'
}
if (@($Versions | Select-Object -Unique).Count -ne $Versions.Count) {
    throw 'Duplicate versions are not allowed.'
}
foreach ($Version in $Versions) {
    if ($Version -cnotin $Supported) {
        throw "Unsupported matrix version: $Version"
    }
}
if ($Mode -eq 'Artifact' -and -not $ArtifactRoot) {
    throw '-ArtifactRoot is required in Artifact mode.'
}
if ($Mode -eq 'Artifact' -and $AllowImagePull) {
    throw '-AllowImagePull is valid only in Container mode.'
}

$RepositoryPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
$ArtifactRunnerPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'maddy-wsl-case.sh') -ErrorAction Stop).Path
$ContainerRunnerPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'maddy-wsl-container-case.sh') -ErrorAction Stop).Path
$DiagnosticRoot = Join-Path ([IO.Path]::GetTempPath()) ("maddyweb-wsl-diagnostics-{0}" -f $PID)

function Convert-ToWslPath {
    param([Parameter(Mandatory = $true)][string] $WindowsPath)
    $Output = & wsl.exe -d $Distro --exec wslpath -a -- $WindowsPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "wslpath failed for a required local path: $Output"
    }
    $Value = ($Output | Select-Object -Last 1).Trim()
    if (-not $Value.StartsWith('/')) {
        throw "wslpath returned a non-absolute path: $Value"
    }
    return $Value
}

function Read-ArtifactChecksum {
    param([Parameter(Mandatory = $true)][string] $Path)
    $ChecksumText = (Get-Content -LiteralPath $Path -Raw).Trim()
    if ($ChecksumText -notmatch '^([0-9A-Fa-f]{64})(?:\s+\*?maddy)?$') {
        throw "Invalid checksum file: $Path"
    }
    return $Matches[1].ToLowerInvariant()
}

# This proves only that the named distribution can execute a local process. It
# does not use SSH or contact a production host.
& wsl.exe -d $Distro --exec true
if ($LASTEXITCODE -ne 0) {
    throw "WSL distribution is unavailable: $Distro"
}

$WslRepository = Convert-ToWslPath -WindowsPath $RepositoryPath
$WslArtifactRunner = Convert-ToWslPath -WindowsPath $ArtifactRunnerPath
$WslContainerRunner = Convert-ToWslPath -WindowsPath $ContainerRunnerPath
$WslDiagnosticRoot = Convert-ToWslPath -WindowsPath $DiagnosticRoot
$Results = [System.Collections.Generic.List[object]]::new()
$Failures = [System.Collections.Generic.List[object]]::new()

$ImageLock = $null
if ($Mode -eq 'Container') {
    $ResolvedLock = (Resolve-Path -LiteralPath $LockFile -ErrorAction Stop).Path
    $ImageLock = Get-Content -LiteralPath $ResolvedLock -Raw | ConvertFrom-Json
    if ($ImageLock.format -cne 'maddyweb-maddy-image-lock-v1') {
        throw 'Image lock format is not recognized.'
    }
    if (@($ImageLock.images.PSObject.Properties.Name).Count -ne $Supported.Count) {
        throw 'Image lock does not contain the complete release set.'
    }
    foreach ($SupportedVersion in $Supported) {
        $Reference = $ImageLock.images.PSObject.Properties[$SupportedVersion].Value
        if ($Reference -cnotmatch '^ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}$') {
            throw "Image lock has an invalid reference for $SupportedVersion"
        }
    }
}
else {
    $ArtifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot -ErrorAction Stop).Path
}

foreach ($Version in $Versions) {
    try {
        if ($Mode -eq 'Container') {
            $Reference = [string] $ImageLock.images.PSObject.Properties[$Version].Value
            $PullPolicy = if ($AllowImagePull) { 'true' } else { 'false' }
            $Output = & wsl.exe -d $Distro --exec bash $WslContainerRunner `
                $Version $Reference $WslRepository $PythonCommand $WslDiagnosticRoot $PullPolicy 2>&1
        }
        else {
            $VersionRoot = Join-Path $ArtifactRoot $Version
            $BinaryPath = Join-Path $VersionRoot 'maddy'
            $ChecksumPath = Join-Path $VersionRoot 'maddy.sha256'
            $ConfigPath = Join-Path $VersionRoot 'maddy.conf'
            foreach ($RequiredPath in @($BinaryPath, $ChecksumPath, $ConfigPath)) {
                $Item = Get-Item -LiteralPath $RequiredPath -Force -ErrorAction Stop
                if ($Item.PSIsContainer -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw "Required artifact must be a regular non-link file: $RequiredPath"
                }
            }
            $ExpectedHash = Read-ArtifactChecksum -Path $ChecksumPath
            $ActualHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($ActualHash -cne $ExpectedHash) {
                throw "Checksum mismatch for Maddy $Version"
            }
            $WslBinary = Convert-ToWslPath -WindowsPath $BinaryPath
            $WslConfig = Convert-ToWslPath -WindowsPath $ConfigPath
            $Output = & wsl.exe -d $Distro --exec bash $WslArtifactRunner `
                $WslBinary $ExpectedHash $WslConfig $Version $WslRepository $PythonCommand 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            throw "case process exited $LASTEXITCODE`: $Output"
        }
        $Case = ($Output | Select-Object -Last 1) | ConvertFrom-Json -ErrorAction Stop
        if ($Case.status -cne 'ok' -or $Case.version -cne $Version) {
            throw 'case returned an invalid result'
        }
        $Results.Add($Case)
    }
    catch {
        $Failures.Add([ordered]@{
            version = $Version
            error = $_.Exception.Message
        })
    }
}

$Report = [ordered]@{
    status = if ($Failures.Count -eq 0) { 'ok' } else { 'failed' }
    mode = $Mode.ToLowerInvariant()
    distro = $Distro
    python = $PythonCommand
    image_pull_authorized = [bool] $AllowImagePull
    versions = @($Results)
    failures = @($Failures)
    diagnostics = if ($Failures.Count -eq 0) { $null } else { $DiagnosticRoot }
}
$Json = $Report | ConvertTo-Json -Depth 8
if ($ReportPath) {
    $Parent = Split-Path -Parent $ReportPath
    if (-not $Parent) {
        $Parent = (Get-Location).Path
    }
    $ResolvedParent = (Resolve-Path -LiteralPath $Parent -ErrorAction Stop).Path
    $OutputPath = Join-Path $ResolvedParent (Split-Path -Leaf $ReportPath)
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Report path already exists: $OutputPath"
    }
    [IO.File]::WriteAllText($OutputPath, $Json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
$Json
if ($Failures.Count -ne 0) {
    throw "$($Failures.Count) Maddy compatibility case(s) failed; no fixture containers were left running."
}
