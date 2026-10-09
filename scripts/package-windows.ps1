[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [ValidateSet('standard', 'events')]
    [string] $Edition = 'standard',

    [string] $DistDir = (Join-Path $PSScriptRoot '..\dist'),
    [string] $InstructionPath = (Join-Path $PSScriptRoot '..\docs\windows-first-start.txt')
)

$ErrorActionPreference = 'Stop'
# The old default command (-Version only) still packages standard. Prefer the
# helper's edition directory, retaining compatibility with the old flat dist.
if (-not $PSBoundParameters.ContainsKey('DistDir')) {
    $editionDir = Join-Path $DistDir $Edition
    if ($Edition -eq 'events' -or (Test-Path -LiteralPath $editionDir -PathType Container)) {
        $DistDir = $editionDir
    }
}
$distPath = (Resolve-Path -LiteralPath $DistDir).ProviderPath
$instruction = (Resolve-Path -LiteralPath $InstructionPath).ProviderPath
$binaryNames = @('netadmin.exe', 'agent.exe')
$archiveName = if ($Edition -eq 'events') { 'NetAdmin-Events-Windows-x64.zip' } else { 'NetAdmin-Windows-x64.zip' }
$productName = if ($Edition -eq 'events') { 'NetAdmin Events' } else { 'NetAdmin' }

function Invoke-BinaryProbe([string] $BinaryPath, [string] $Argument) {
    $name = [System.IO.Path]::GetFileName($BinaryPath)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $BinaryPath
    $startInfo.Arguments = $Argument
    $startInfo.WorkingDirectory = $distPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "Cannot probe $name" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Binary probe timed out: $name $Argument"
        }
        $output = $stdout.GetAwaiter().GetResult().Trim()
        $errorOutput = $stderr.GetAwaiter().GetResult().Trim()
        if ($process.ExitCode -ne 0) {
            throw "Binary probe failed: $name $Argument (exit $($process.ExitCode), $errorOutput)"
        }
        if ($output.Length -gt 1024 -or $output.Contains("`n") -or $output.Contains("`r")) {
            throw "Invalid binary probe output: $name $Argument"
        }
        return $output
    } finally {
        $process.Dispose()
    }
}

# Probe the exact files being shipped before touching an existing archive.
# Server and standalone agent must agree, including the embedded agent edition.
$releaseVersion = $null
foreach ($name in $binaryNames) {
    $binaryPath = Join-Path $distPath $name
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Missing release binary: $binaryPath"
    }
    $binaryEdition = Invoke-BinaryProbe $binaryPath '-edition'
    if ($binaryEdition -cne $Edition) {
        throw "Wrong edition in ${name}: expected $Edition, got $binaryEdition"
    }
    $output = Invoke-BinaryProbe $binaryPath '-version'
    if ($name -eq 'agent.exe') {
        # The agent's -version is a numeric wire contract for self-update.
        # Its separate build probe includes edition and Git metadata.
        if ($output -cne $Version) {
            throw "Wrong release version in ${name}: expected $Version, got $output"
        }
        $output = Invoke-BinaryProbe $binaryPath '-build-version'
    }
    $versionPrefix = [regex]::Escape("$productName $Version")
    if ($output -cnotmatch ("^$versionPrefix(?: · [0-9a-fA-F]+(?: \(с правками\))?)?$") -or
        ($null -ne $releaseVersion -and $output -cne $releaseVersion)) {
        throw "Wrong or inconsistent release version in ${name}: expected $productName $Version, got $output"
    }
    $releaseVersion = $output
    Write-Host "$name : $output ($binaryEdition)"
}
$embeddedEdition = Invoke-BinaryProbe (Join-Path $distPath 'netadmin.exe') '-embedded-agent-edition'
if ($embeddedEdition -cne $Edition) {
    throw "Wrong embedded agent edition: expected $Edition, got $embeddedEdition"
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
    $startText = [System.IO.File]::ReadAllText($instruction)
    if ($Edition -eq 'events') {
        $eventsIntro = @'
NetAdmin Events — редакция с событиями Windows
============================================
Сервер, встроенный агент и agent.exe в этом комплекте относятся к Events.
Сбор событий выключен по умолчанию. Настройте HTTPS и явно включите сбор
для выбранных ПК в разделе «События Windows» → «Сбор». Для смены редакции агента
нужна переустановка; обычное самообновление редакцию не меняет.
По новым событиям создаются карточки: серии неудачных входов, очистка журнала
и установка службы. Откройте карточку, проверьте события, назначьте
ответственного и сохраните разбор. Пороги и временные исключения находятся
в разделе «Настройки» → «Правила и исключения». Доступ — только администраторам.
Основные разделы Events: «Обнаружения», «Журнал», «Сбор» и «Настройки».
В разделе «Сбор» видны потеря связи, ошибки сбора и задержка очереди.
Копии Events создаются отдельно в подкаталоге events общего каталога копий,
по тому же расписанию. Создание, проверка и восстановление доступны в
«Настройки» → «Резервные копии» внутри Events. После восстановления перезапустите сервер и включите сбор
для нужных ПК заново; прежняя база сохраняется рядом для отката.
Описание и ограничения: https://github.com/abdlvmx/NetAdmin/blob/main/docs/events.md

'@
        $startText = $eventsIntro + "`r`n" + $startText
    }
    [System.IO.File]::WriteAllText((Join-Path $packageDir 'START-HERE.txt'), $startText, $utf8Bom)

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
