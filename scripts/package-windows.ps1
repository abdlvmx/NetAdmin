[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [string] $DistDir = (Join-Path $PSScriptRoot '..\dist'),
    [string] $InstructionPath = (Join-Path $PSScriptRoot '..\docs\windows-first-start.txt')
)

$ErrorActionPreference = 'Stop'
$distPath = (Resolve-Path -LiteralPath $DistDir).ProviderPath
$instruction = (Resolve-Path -LiteralPath $InstructionPath).ProviderPath
$binaryNames = @('netadmin.exe', 'agent.exe')
$archiveName = 'NetAdmin-Windows-x64.zip'

# Probe the files actually being shipped. A failed build or missing version stamp
# must not produce a package with a misleading release number.
foreach ($name in $binaryNames) {
    $binaryPath = Join-Path $distPath $name
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Missing release binary: $binaryPath"
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $binaryPath
    $startInfo.Arguments = '-version'
    $startInfo.WorkingDirectory = $distPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "Cannot probe $name" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw "Version probe timed out: $name"
        }
        $output = $stdout.GetAwaiter().GetResult().Trim()
        $errorOutput = $stderr.GetAwaiter().GetResult().Trim()
        if ($process.ExitCode -ne 0) {
            throw "Version probe failed: $name ($errorOutput)"
        }
        if ($output.Length -gt 1024 -or $output -notmatch ('(^|\s)' + [regex]::Escape($Version) + '(\s|$)')) {
            throw "Wrong release version in ${name}: expected $Version, got $output"
        }
        Write-Host "$name : $output"
    } finally {
        $process.Dispose()
    }
}

$nonce = [guid]::NewGuid().ToString('N')
$packageDir = Join-Path $distPath ".package-$nonce"
$temporaryArchive = Join-Path $distPath ".package-$nonce.zip"
$previousArchive = Join-Path $distPath ".package-$nonce.previous.zip"
$archivePath = Join-Path $distPath $archiveName
$checksumLines = @()

try {
    New-Item -ItemType Directory -Path $packageDir | Out-Null
    foreach ($name in $binaryNames) {
        $source = Join-Path $distPath $name
        $target = Join-Path $packageDir $name
        Copy-Item -LiteralPath $source -Destination $target
        $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        $checksumLines += "$hash  $name"
    }
    [System.IO.File]::WriteAllLines((Join-Path $packageDir 'SHA256SUMS.txt'), $checksumLines, [System.Text.Encoding]::ASCII)
    # A BOM makes the Russian instructions readable in older Windows Notepad.
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText((Join-Path $packageDir 'START-HERE.txt'), [System.IO.File]::ReadAllText($instruction), $utf8Bom)

    $memberNames = @('netadmin.exe', 'agent.exe', 'START-HERE.txt', 'SHA256SUMS.txt')
    $packageFiles = @($memberNames | ForEach-Object { Join-Path $packageDir $_ })
    Compress-Archive -LiteralPath $packageFiles -DestinationPath $temporaryArchive -CompressionLevel Optimal

    # Verify the archive itself, not just the directory used to construct it.
    # Explicit membership prevents accidental inclusion of a developer's config,
    # database, enrollment token or diagnostic logs.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($temporaryArchive)
    try {
        $actualNames = @($zip.Entries | ForEach-Object { $_.FullName })
        if ($actualNames.Count -ne $memberNames.Count -or (Compare-Object $memberNames $actualNames)) {
            throw 'Unexpected files in Windows release archive.'
        }
        foreach ($line in $checksumLines) {
            $hash, $name = $line -split '  ', 2
            $entry = $zip.GetEntry($name)
            $stream = $entry.Open()
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $actualHash = ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
                if ($actualHash -ne $hash) { throw "Archive checksum mismatch: $name" }
            } finally {
                $sha.Dispose()
                $stream.Dispose()
            }
        }
    } finally {
        $zip.Dispose()
    }

    if (Test-Path -LiteralPath $archivePath) {
        [System.IO.File]::Replace($temporaryArchive, $archivePath, $previousArchive)
    } else {
        [System.IO.File]::Move($temporaryArchive, $archivePath)
    }
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    # The archive contains hashes of EXEs; the release-level file also hashes ZIP.
    [System.IO.File]::WriteAllLines((Join-Path $distPath 'SHA256SUMS.txt'), @($checksumLines) + "$archiveHash  $archiveName", [System.Text.Encoding]::ASCII)
    Write-Host "Verified Windows package: $archivePath"
} finally {
    # Only remove this invocation's temporary paths, with a checked parent.
    foreach ($temporaryPath in @($packageDir, $temporaryArchive, $previousArchive)) {
        $fullPath = [System.IO.Path]::GetFullPath($temporaryPath)
        if ([System.IO.Path]::GetDirectoryName($fullPath) -ne $distPath -or [System.IO.Path]::GetFileName($fullPath) -notlike ".package-$nonce*") {
            throw "Refusing cleanup outside package directory: $fullPath"
        }
        if (Test-Path -LiteralPath $fullPath) {
            Remove-Item -LiteralPath $fullPath -Recurse -Force
        }
    }
}
