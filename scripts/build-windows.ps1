[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [ValidateSet('standard', 'events', 'all')]
    [string] $Edition = 'standard',

    [string] $DistDir = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath.TrimEnd('\', '/')
$distPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DistDir).TrimEnd('\', '/')
$workspacePrefix = $workspace + [System.IO.Path]::DirectorySeparatorChar
if (-not $distPath.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Build output must be below the workspace: $distPath"
}
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Windows release builds must run on Windows.'
}

# Every server embeds the same on-disk agent.exe. A workspace-wide mutex prevents
# another invocation from replacing it between the agent and server builds.
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $workspaceHash = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($workspace.ToLowerInvariant())))).Replace('-', '')
} finally {
    $sha.Dispose()
}
$mutex = New-Object System.Threading.Mutex($false, "Local\NetAdmin-WindowsBuild-$workspaceHash")
$locked = $false
$oldGoOS = [System.Environment]::GetEnvironmentVariable('GOOS', 'Process')
$oldGoArch = [System.Environment]::GetEnvironmentVariable('GOARCH', 'Process')
$locationPushed = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another Windows build is using this workspace; wait for it to finish.' }
    Push-Location -LiteralPath $workspace
    $locationPushed = $true
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $linkerFlags = "-s -w -X netadmin/internal/version.Value=$Version"
    $editions = if ($Edition -eq 'all') { @('standard', 'events') } else { @($Edition) }
    $embeddedAgent = Join-Path $workspace 'internal\agentbin\bin\agent.exe'
    $nonce = [guid]::NewGuid().ToString('N')
    $stageParent = Join-Path $workspace '_t'
    $stagePath = Join-Path $stageParent "windows-build-$nonce"

    # Keep this loop sequential: each agent must be copied before its server is
    # compiled. _t is Git-ignored; writing EXEs into an unignored DistDir before
    # the last build would change vcs.modified between the paired binaries.
    try {
        New-Item -ItemType Directory -Path $stagePath -Force | Out-Null
        foreach ($currentEdition in $editions) {
            $editionStage = Join-Path $stagePath $currentEdition
            New-Item -ItemType Directory -Path $editionStage | Out-Null
            $buildTags = if ($currentEdition -eq 'events') { 'securityevents' } else { '' }
            $agentPath = Join-Path $editionStage 'agent.exe'
            $serverPath = Join-Path $editionStage 'netadmin.exe'
            Write-Host "Building NetAdmin $currentEdition $Version (Windows x64)"
            # Explicit -tags also overrides an inherited GOFLAGS edition tag.
            & go build -trimpath "-tags=$buildTags" -ldflags $linkerFlags -o $agentPath ./cmd/agent
            if ($LASTEXITCODE -ne 0) { throw "Agent build failed for $currentEdition (exit $LASTEXITCODE)." }
            Copy-Item -LiteralPath $agentPath -Destination $embeddedAgent -Force
            & go build -trimpath "-tags=$buildTags" -ldflags $linkerFlags -o $serverPath ./cmd/netadmin
            if ($LASTEXITCODE -ne 0) { throw "Server build failed for $currentEdition (exit $LASTEXITCODE)." }
        }
        # Publish only after all Go builds finish; output directories are separate.
        foreach ($currentEdition in $editions) {
            $editionStage = Join-Path $stagePath $currentEdition
            $outputPath = Join-Path $distPath $currentEdition
            New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $editionStage 'agent.exe') -Destination (Join-Path $outputPath 'agent.exe') -Force
            Copy-Item -LiteralPath (Join-Path $editionStage 'netadmin.exe') -Destination (Join-Path $outputPath 'netadmin.exe') -Force
            Write-Host "Built $currentEdition in $outputPath"
        }
    } finally {
        # Remove only this invocation's stage, never an arbitrary DistDir.
        $fullStage = [System.IO.Path]::GetFullPath($stagePath)
        if (-not $fullStage.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            [System.IO.Path]::GetDirectoryName($fullStage) -ne $stageParent -or
            [System.IO.Path]::GetFileName($fullStage) -ne "windows-build-$nonce") {
            throw "Refusing cleanup outside the checked build stage: $fullStage"
        }
        if (Test-Path -LiteralPath $fullStage) { Remove-Item -LiteralPath $fullStage -Recurse -Force }
    }
} finally {
    [System.Environment]::SetEnvironmentVariable('GOOS', $oldGoOS, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOARCH', $oldGoArch, 'Process')
    if ($locationPushed) { Pop-Location }
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
