#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Install", "Update", "Verify", "Uninstall")]
    [string]$Action = "Install",
    [string]$PackagePath,
    [string]$ChecksumPath,
    [string]$ReleaseManifestPath,
    [string]$NpmPrefix,
    [switch]$SkipPathUpdate
)

trap {
    $message = if ($_.Exception -and $_.Exception.Message) {
        $_.Exception.Message
    } else {
        "The operation failed."
    }
    [Console]::Error.WriteLine("CoCodex installer failed: $message")
    exit 1
}

$ErrorActionPreference = "Stop"
$PackageName = "@sdanderosa/cocodex"
$RequiredCommands = @("cocodex", "ccx", "cocodex-server", "ccx-server", "ocx")

function Resolve-NpmCommand {
    $candidate = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $candidate) {
        $candidate = Get-Command npm -ErrorAction SilentlyContinue
    }
    if (-not $candidate) {
        throw "npm 10 or newer is required. Install Node.js 22.12 or newer, then run this installer again."
    }
    return $candidate.Source
}

function Assert-NodeVersion {
    $candidate = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $candidate) {
        $candidate = Get-Command node -ErrorAction SilentlyContinue
    }
    if (-not $candidate) {
        throw "Node.js 22.12 or newer is required."
    }
    $version = (& $candidate.Source -p "process.versions.node").Trim()
    if ($LASTEXITCODE -ne 0 -or -not $version) {
        throw "Unable to read the installed Node.js version."
    }
    try {
        $parsed = [version]$version
    } catch {
        throw "Unable to parse the installed Node.js version: v$version"
    }
    if ($parsed -lt [version]"22.12.0") {
        throw "Node.js 22.12 or newer is required. Current version: v$version"
    }
    return $version
}

function Assert-NpmVersion([string]$Npm) {
    $version = (& $Npm --version).Trim()
    $major = 0
    if ($LASTEXITCODE -ne 0 -or -not [int]::TryParse($version.Split(".")[0], [ref]$major) -or $major -lt 10) {
        throw "npm 10 or newer is required. Current version: $version"
    }
    return $version
}

function Resolve-Prefix([string]$Npm, [string]$RequestedPrefix) {
    if ($RequestedPrefix) {
        return [System.IO.Path]::GetFullPath($RequestedPrefix)
    }
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if (-not $localAppData) {
        throw "Unable to resolve the Windows local application-data directory."
    }
    return [System.IO.Path]::GetFullPath((Join-Path $localAppData "CoCodex\app"))
}

function Resolve-CommandShim([string]$Prefix, [string]$Name) {
    $commandRoot = Join-Path $Prefix "node_modules\.bin"
    $windowsShim = Join-Path $commandRoot "$Name.cmd"
    if (Test-Path -LiteralPath $windowsShim -PathType Leaf) {
        return $windowsShim
    }
    $plainShim = Join-Path $commandRoot $Name
    if (Test-Path -LiteralPath $plainShim -PathType Leaf) {
        return $plainShim
    }
    throw "The installed package did not create the '$Name' command in $commandRoot."
}

function Read-BoundedJson([string]$Path, [int64]$MaxBytes, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular file."
    }
    if ($item.Length -gt $MaxBytes) {
        throw "$Label exceeds the $MaxBytes-byte limit."
    }
    try {
        return (Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json)
    } catch {
        throw "$Label is not valid JSON."
    }
}

function Get-FileSha256([string]$Path) {
    $stream = $null
    $sha256 = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $digest = $sha256.ComputeHash($stream)
        return ([System.BitConverter]::ToString($digest)).Replace("-", "")
    } finally {
        if ($sha256) { $sha256.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Assert-InstalledPackage([string]$Prefix, [string]$ExpectedVersion, [string]$ExpectedShrinkwrapSha256) {
    $packageRoot = Join-Path $Prefix "node_modules\@sdanderosa\cocodex"
    $manifestPath = Join-Path $packageRoot "package.json"
    $manifest = Read-BoundedJson $manifestPath 262144 "installed CoCodex package manifest"
    if ($manifest.name -ne $PackageName) {
        throw "The installed package identity is '$($manifest.name)', expected '$PackageName'."
    }
    if ($ExpectedVersion -and $manifest.version -ne $ExpectedVersion) {
        throw "The installed CoCodex version is '$($manifest.version)', expected '$ExpectedVersion'."
    }
    if (-not ($manifest.version -match "^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")) {
        throw "The installed CoCodex package has an invalid version."
    }
    $shrinkwrap = Join-Path $packageRoot "npm-shrinkwrap.json"
    $shrinkwrapItem = Get-Item -LiteralPath $shrinkwrap -Force
    if ($shrinkwrapItem.PSIsContainer -or (($shrinkwrapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The installed CoCodex dependency lock is not a regular file."
    }
    if ($ExpectedShrinkwrapSha256) {
        $actual = Get-FileSha256 $shrinkwrap
        if ($actual -ne $ExpectedShrinkwrapSha256.ToUpperInvariant()) {
            throw "The installed CoCodex dependency lock does not match the verified release."
        }
    }
    return $manifest
}

function Assert-InstalledCommands([string]$Prefix, [string]$ExpectedVersion = "", [string]$ExpectedShrinkwrapSha256 = "") {
    [void](Assert-InstalledPackage $Prefix $ExpectedVersion $ExpectedShrinkwrapSha256)
    foreach ($name in $RequiredCommands) {
        [void](Resolve-CommandShim $Prefix $name)
    }
    $client = Resolve-CommandShim $Prefix "cocodex"
    $server = Resolve-CommandShim $Prefix "cocodex-server"
    $proxy = Resolve-CommandShim $Prefix "ocx"
    & $client --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The installed CoCodex Client command failed its help smoke test."
    }
    & $server --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The installed CoCodex Server command failed its help smoke test."
    }
    & $proxy --version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The installed OpenCodex-compatible local runtime failed its version smoke test."
    }
}

function Add-PrefixToUserPath([string]$Prefix) {
    $Prefix = Join-Path $Prefix "node_modules\.bin"
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($current -split ";" | Where-Object { $_ -and $_.Trim() })
    $alreadyPresent = $parts | Where-Object {
        [string]::Equals(
            [System.IO.Path]::GetFullPath($_.Trim()),
            [System.IO.Path]::GetFullPath($Prefix),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    }
    if (-not $alreadyPresent) {
        $next = (@($parts) + $Prefix) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $next, "User")
    }
    if (-not (($env:Path -split ";") | Where-Object {
        $_ -and [string]::Equals(
            [System.IO.Path]::GetFullPath($_.Trim()),
            [System.IO.Path]::GetFullPath($Prefix),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    })) {
        $env:Path = "$Prefix;$env:Path"
    }
}

function Resolve-ReleaseFile([string]$Requested, [string]$Pattern, [string]$Label) {
    if ($Requested) {
        $resolved = [System.IO.Path]::GetFullPath($Requested)
    } else {
        $matches = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter $Pattern -File)
        if ($matches.Count -ne 1) {
            throw "Expected exactly one $Label beside this installer; found $($matches.Count)."
        }
        $resolved = $matches[0].FullName
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        return $item.FullName
    }
    throw "$Label must be a regular file, not a directory or reparse point."
}

function Assert-BundleFileChecksum([string]$Path, [string]$ChecksumFile, [string]$Label) {
    $archiveName = [System.IO.Path]::GetFileName($Path)
    $checksumItem = Get-Item -LiteralPath $ChecksumFile -Force
    if ($checksumItem.Length -gt 65536) {
        throw "The checksum file exceeds the 65536-byte validation limit."
    }
    $matches = @(Get-Content -LiteralPath $checksumItem.FullName |
        Where-Object { $_ -match ("^[A-Fa-f0-9]{64}\s+\*?" + [regex]::Escape($archiveName) + "$") })
    if ($matches.Count -ne 1) {
        throw "The checksum file must contain exactly one SHA-256 entry for $Label ($archiveName); found $($matches.Count)."
    }
    $line = $matches[0]
    $expected = ($line -split "\s+")[0].ToUpperInvariant()
    $actual = Get-FileSha256 $Path
    if (-not [string]::Equals($expected, $actual, [System.StringComparison]::Ordinal)) {
        throw "CoCodex $Label checksum verification failed. Expected $expected, received $actual."
    }
    return $actual
}

function Read-ExactBytes([System.IO.Stream]$Stream, [byte[]]$Buffer, [int]$Offset, [int]$Count) {
    $total = 0
    while ($total -lt $Count) {
        $read = $Stream.Read($Buffer, $Offset + $total, $Count - $total)
        if ($read -eq 0) {
            break
        }
        $total += $read
    }
    return $total
}

function Skip-ExactBytes([System.IO.Stream]$Stream, [int64]$Count) {
    $buffer = New-Object byte[] 65536
    $remaining = $Count
    while ($remaining -gt 0) {
        $next = [int][Math]::Min($remaining, $buffer.Length)
        $read = Read-ExactBytes $Stream $buffer 0 $next
        if ($read -ne $next) {
            throw "CoCodex archive ended before a complete tar entry was read."
        }
        $remaining -= $read
    }
}

function Read-TarTextEntry([string]$Archive, [string]$ExpectedName, [int64]$MaxBytes) {
    $file = [System.IO.File]::OpenRead($Archive)
    $gzip = New-Object System.IO.Compression.GZipStream($file, [System.IO.Compression.CompressionMode]::Decompress)
    $header = New-Object byte[] 512
    $ascii = [System.Text.Encoding]::ASCII
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $found = $null
    $entries = 0
    $expanded = [int64]0
    try {
        while ($true) {
            $headerRead = Read-ExactBytes $gzip $header 0 512
            if ($headerRead -eq 0) {
                break
            }
            if ($headerRead -ne 512) {
                throw "CoCodex archive has a truncated tar header."
            }
            $isZero = $true
            foreach ($value in $header) {
                if ($value -ne 0) {
                    $isZero = $false
                    break
                }
            }
            if ($isZero) {
                break
            }
            $entries += 1
            if ($entries -gt 100000) {
                throw "CoCodex archive contains too many entries."
            }
            $name = $ascii.GetString($header, 0, 100).TrimEnd([char]0)
            $prefix = $ascii.GetString($header, 345, 155).TrimEnd([char]0)
            if ($prefix) {
                $name = "$prefix/$name"
            }
            $sizeText = $ascii.GetString($header, 124, 12).Trim([char[]]@([char]0, [char]32))
            if (-not $sizeText) {
                $size = [int64]0
            } elseif ($sizeText -match "^[0-7]+$") {
                try {
                    $size = [Convert]::ToInt64($sizeText, 8)
                } catch {
                    throw "CoCodex archive contains an invalid tar entry size."
                }
            } else {
                throw "CoCodex archive contains an unsupported tar entry size."
            }
            $padding = (512 - ($size % 512)) % 512
            $expanded += 512 + $size + $padding
            if ($expanded -gt 1073741824) {
                throw "CoCodex archive expands beyond the 1 GiB validation limit."
            }
            if ($name -eq $ExpectedName) {
                if ($null -ne $found) {
                    throw "CoCodex archive contains a duplicate $ExpectedName entry."
                }
                if ($size -gt $MaxBytes) {
                    throw "CoCodex archive $ExpectedName exceeds the validation limit."
                }
                $bytes = New-Object byte[] ([int]$size)
                if ((Read-ExactBytes $gzip $bytes 0 ([int]$size)) -ne $size) {
                    throw "CoCodex archive has a truncated $ExpectedName entry."
                }
                try {
                    $found = $utf8.GetString($bytes)
                } catch {
                    throw "CoCodex archive $ExpectedName entry is not valid UTF-8."
                }
                Skip-ExactBytes $gzip $padding
            } else {
                Skip-ExactBytes $gzip ($size + $padding)
            }
        }
    } finally {
        $gzip.Dispose()
        $file.Dispose()
    }
    if ($null -eq $found) {
        throw "CoCodex archive does not contain $ExpectedName."
    }
    return $found
}

function Get-TextSha256([string]$Text) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Text))).Replace("-", ""))
    } finally {
        $sha.Dispose()
    }
}

function Assert-ReleaseArchive([string]$Archive, $Release) {
    if ($Release.product -ne "CoCodex" -or $Release.channel -ne "private-alpha" -or $Release.packageName -ne $PackageName) {
        throw "RELEASE.json does not identify a CoCodex private-alpha package."
    }
    if (-not ($Release.version -match "^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")) {
        throw "RELEASE.json contains an invalid version."
    }
    if ($Release.archive -ne [System.IO.Path]::GetFileName($Archive)) {
        throw "RELEASE.json does not name the selected package archive."
    }
    if (-not ($Release.sourceCommit -match "^[A-Fa-f0-9]{40}$") -or
        -not ($Release.sourceTree -match "^[A-Fa-f0-9]{40}$") -or
        -not ($Release.guiSha256 -match "^[A-Fa-f0-9]{64}$") -or
        -not ($Release.shrinkwrapSha256 -match "^[A-Fa-f0-9]{64}$")) {
        throw "RELEASE.json contains invalid source or content provenance."
    }
    if ($Release.requiredNodeVersion -ne "22.12.0" -or [int]$Release.requiredNpmMajor -ne 10) {
        throw "RELEASE.json contains an unsupported Node.js or npm requirement."
    }
    if ((@($Release.commands) -join "`0") -ne ($RequiredCommands -join "`0")) {
        throw "RELEASE.json contains an unexpected command set."
    }
    $packageText = Read-TarTextEntry $Archive "package/package.json" 262144
    try {
        $package = $packageText | ConvertFrom-Json
    } catch {
        throw "CoCodex archive package.json is invalid."
    }
    if ($package.name -ne $PackageName -or $package.version -ne $Release.version) {
        throw "CoCodex archive package identity/version does not match RELEASE.json."
    }
    if (@($package.scripts.PSObject.Properties).Count -ne 0) {
        throw "CoCodex archive package must not contain lifecycle scripts."
    }
    $shrinkwrapText = Read-TarTextEntry $Archive "package/npm-shrinkwrap.json" 2097152
    if ((Get-TextSha256 $shrinkwrapText) -ne $Release.shrinkwrapSha256.ToUpperInvariant()) {
        throw "CoCodex archive dependency lock does not match RELEASE.json."
    }
    return [pscustomobject]@{
        Version = $Release.version
        Package = $package
    }
}

function Write-InstallRootManifest([string]$Prefix, [string]$Archive, $Package) {
    if (-not (Test-Path -LiteralPath $Prefix -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($Prefix)
    }
    $manifestPath = Join-Path $Prefix "package.json"
    $temporaryPath = Join-Path $Prefix "package.json.cocodex-new"
    $dependency = [ordered]@{}
    $dependency[$PackageName] = [System.IO.Path]::GetFullPath($Archive)
    $root = [ordered]@{
        name = "cocodex-private-alpha-install-root"
        version = "1.0.0"
        private = $true
        dependencies = $dependency
        overrides = $Package.overrides
    }
    [System.IO.File]::WriteAllText(
        $temporaryPath,
        (($root | ConvertTo-Json -Depth 32) + "`n"),
        (New-Object System.Text.UTF8Encoding($false))
    )
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $backupPath = Join-Path $Prefix "package.json.cocodex-old"
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            [System.IO.File]::Delete($backupPath)
        }
        [System.IO.File]::Replace($temporaryPath, $manifestPath, $backupPath, $true)
        [System.IO.File]::Delete($backupPath)
    } else {
        [System.IO.File]::Move($temporaryPath, $manifestPath)
    }
}

function Assert-CoCodexStopped([string]$Prefix) {
    $packageRoot = [System.IO.Path]::GetFullPath((Join-Path $Prefix "node_modules\@sdanderosa\cocodex"))
    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    } catch {
        throw "Unable to prove CoCodex processes are stopped. Close CoCodex Client, Server, and ocx, then retry."
    }
    $ignoredShellAncestors = New-Object "System.Collections.Generic.HashSet[int]"
    $ancestorPid = [int]$PID
    while ($ancestorPid -gt 0) {
        $ancestor = $processes | Where-Object { [int]$_.ProcessId -eq $ancestorPid } | Select-Object -First 1
        if (-not $ancestor) {
            break
        }
        $ancestorName = [string]$ancestor.Name
        if ($ancestorPid -ne $PID -and $ancestorName -notin @("powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe")) {
            break
        }
        [void]$ignoredShellAncestors.Add($ancestorPid)
        $ancestorPid = [int]$ancestor.ParentProcessId
    }
    foreach ($process in $processes) {
        if ($ignoredShellAncestors.Contains([int]$process.ProcessId)) {
            continue
        }
        $executable = [string]$process.ExecutablePath
        $commandLine = [string]$process.CommandLine
        $underPrefix = $executable -and $executable.StartsWith(
            ([System.IO.Path]::GetFullPath($Prefix).TrimEnd("\") + "\"),
            [System.StringComparison]::OrdinalIgnoreCase
        )
        $usesPackage = $commandLine -and ($commandLine.IndexOf(
            $packageRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -ge 0)
        if ($underPrefix -or $usesPackage) {
            throw "CoCodex process $($process.ProcessId) is still running. Stop Client, Server, and ocx before $Action."
        }
    }
}

$archive = $null
$verifiedHash = $null
$release = $null
$releaseVersion = ""
$releasePackage = $null
if ($Action -eq "Install" -or $Action -eq "Update") {
    $archive = Resolve-ReleaseFile $PackagePath "*.tgz" "CoCodex package archive"
    $checksum = Resolve-ReleaseFile $ChecksumPath "SHA256SUMS.txt" "checksum file"
    $releasePath = Resolve-ReleaseFile $ReleaseManifestPath "RELEASE.json" "release manifest"
    $verifiedHash = Assert-BundleFileChecksum $archive $checksum "package archive"
    [void](Assert-BundleFileChecksum $releasePath $checksum "release manifest")
    [void](Assert-BundleFileChecksum $PSCommandPath $checksum "installer")
    $release = Read-BoundedJson $releasePath 65536 "RELEASE.json"
    if ($release.sha256.ToUpperInvariant() -ne $verifiedHash) {
        throw "RELEASE.json archive digest does not match the verified package."
    }
    $releaseArchive = Assert-ReleaseArchive $archive $release
    $releaseVersion = $releaseArchive.Version
    $releasePackage = $releaseArchive.Package
}

$npm = Resolve-NpmCommand
$nodeVersion = Assert-NodeVersion
$npmVersion = Assert-NpmVersion $npm
$prefix = Resolve-Prefix $npm $NpmPrefix

if ($Action -eq "Uninstall") {
    Assert-CoCodexStopped $prefix
    & $npm uninstall --prefix $prefix $PackageName
    if ($LASTEXITCODE -ne 0) {
        throw "npm uninstall failed with exit code $LASTEXITCODE."
    }
    foreach ($metadata in @("package.json", "package-lock.json")) {
        $metadataPath = Join-Path $prefix $metadata
        if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
            [System.IO.File]::Delete($metadataPath)
        }
    }
    Write-Host "CoCodex application files were removed." -ForegroundColor Green
    Write-Host "Client state (~\.cocodex), Server state (~\.cocodex-server), OpenCodex state, and Codex state were preserved."
    exit 0
}

if ($Action -eq "Verify") {
    Assert-InstalledCommands $prefix
    Write-Host "CoCodex Client, CoCodex Server, and the OpenCodex-compatible local runtime are installed and runnable." -ForegroundColor Green
    exit 0
}

if ($Action -eq "Update" -or (
    $Action -eq "Install" -and
    (Test-Path -LiteralPath (Join-Path $prefix "node_modules\@sdanderosa\cocodex") -PathType Container)
)) {
    Assert-CoCodexStopped $prefix
}

Write-Host "$Action CoCodex private alpha with Node v$nodeVersion and npm v$npmVersion..." -ForegroundColor Cyan
Write-InstallRootManifest $prefix $archive $releasePackage
& $npm install --prefix $prefix --no-audit --no-fund
if ($LASTEXITCODE -ne 0) {
    throw "npm install failed with exit code $LASTEXITCODE. Existing CoCodex state was not removed."
}

Assert-InstalledCommands $prefix $releaseVersion $release.shrinkwrapSha256
if (-not $SkipPathUpdate) {
    Add-PrefixToUserPath $prefix
}

Write-Host "CoCodex private alpha is installed and verified." -ForegroundColor Green
Write-Host "Package SHA-256: $verifiedHash"
Write-Host "Commands: cocodex, ccx, cocodex-server, ccx-server, ocx"
Write-Host "Client and Server state directories are separate and are preserved by future package updates."
