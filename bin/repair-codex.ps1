param(
  [switch]$DryRun,
  [switch]$NoPause
)

$ErrorActionPreference = "Stop"
$configPath = Join-Path $env:USERPROFILE ".opencodex\config.json"
$ocxPath = Join-Path $env:APPDATA "npm\ocx.cmd"
$port = 10100
$backupPath = $null

function Write-Repair([string]$message, [ConsoleColor]$color = [ConsoleColor]::Gray) {
  Write-Host $message -ForegroundColor $color
}

function Invoke-Ocx([string[]]$arguments) {
  if (-not (Test-Path -LiteralPath $ocxPath -PathType Leaf)) {
    throw "ocx.cmd was not found at $ocxPath"
  }
  & $ocxPath @arguments
  return $LASTEXITCODE
}

function New-ConfigBackup {
  if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { return $null }
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  for ($attempt = 0; $attempt -lt 100; $attempt += 1) {
    $suffix = if ($attempt -eq 0) { "" } else { "-$attempt" }
    $candidate = "$configPath.repair-$stamp$suffix.bak"
    try {
      [IO.File]::Copy($configPath, $candidate, $false)
      $sourceHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
      $backupHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
      if ($sourceHash -ne $backupHash) { throw "Config backup hash mismatch" }
      return $candidate
    } catch [IO.IOException] {
      if (Test-Path -LiteralPath $candidate) { continue }
      throw
    }
  }
  throw "Could not allocate a unique repair backup path"
}

function Get-PortOwner {
  $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $listener) { return $null }
  $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
  return [pscustomobject]@{
    LocalAddress = $listener.LocalAddress
    Port = $port
    Pid = $listener.OwningProcess
    ProcessName = $process.Name
    ExecutablePath = $process.ExecutablePath
  }
}

function Get-JsonEndpoint([string]$path, [int]$timeoutSeconds = 4) {
  try {
    $raw = & curl.exe --silent --show-error --max-time $timeoutSeconds "http://127.0.0.1:$port$path" 2>$null | Out-String
    if (-not $raw.Trim()) { return $null }
    return $raw | ConvertFrom-Json
  } catch { return $null }
}

function Wait-Health {
  $deadline = (Get-Date).AddSeconds(8)
  while ((Get-Date) -lt $deadline) {
    $health = Get-JsonEndpoint "/healthz" 1
    if ($health.status -eq "ok" -and $health.service -eq "opencodex") { return $health }
    Start-Sleep -Milliseconds 250
  }
  return $null
}

function Restore-Native {
  Write-Repair "Restoring native Codex configuration..." Yellow
  if ($DryRun) {
    Write-Repair "DRY RUN: would run ocx restore; no configuration or process will be changed." DarkYellow
    return $true
  }
  $exitCode = Invoke-Ocx @("restore")
  if ($exitCode -ne 0) {
    Write-Repair "Native restore failed (exit $exitCode). Run ocx restore from a terminal and inspect the output." Red
    return $false
  }
  Write-Repair "Native Codex fallback restored. Codex can run without the local proxy." Green
  return $true
}

try {
  Write-Repair "CoCodex Safe Repair" Cyan

  $backupPath = New-ConfigBackup
  if ($backupPath) { Write-Repair "Config backup: $backupPath" DarkGray }

  $config = if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
  } else { $null }
  if ($null -ne $config -and $null -ne $config.port) {
    try {
      $candidatePort = [Convert]::ToInt32($config.port)
      if ($candidatePort -gt 0 -and $candidatePort -le 65535) { $port = $candidatePort }
    } catch { }
  }
  Write-Repair "This repair never stops or adopts an unknown listener on port $port."

  $owner = Get-PortOwner
  $health = Get-JsonEndpoint "/healthz"
  $ready = Get-JsonEndpoint "/readyz"
  $mode = $config.providers.openai.codexAccountMode
  Write-Repair "OpenAI account mode: $mode"
  if ($owner) {
    Write-Repair "Port $port is occupied by PID $($owner.Pid) ($($owner.ExecutablePath))." Yellow
  } else {
    Write-Repair "Port $port is not listening."
  }

  if (-not $health -and -not $owner) {
    Write-Repair "No listener is present; asking the installed service to start." Yellow
    if (-not $DryRun) {
      [void](Invoke-Ocx @("service", "start"))
      $health = Wait-Health
    } else {
      Write-Repair "DRY RUN: would run ocx service start; no service or process will be changed." DarkYellow
    }
  }

  $ready = Get-JsonEndpoint "/readyz"
  $readyOk = $ready.status -eq "ok" -and $ready.code -eq "ready" -and $ready.checks.credentials -eq $true
  if (-not $readyOk) {
    if ($owner) {
      Write-Repair "Proxy readiness was not proven; leaving the existing listener untouched." Yellow
    } else {
      Write-Repair "Proxy readiness was not proven." Yellow
    }
    if (-not (Restore-Native)) { exit 1 }
  } else {
    Write-Repair "Proxy readiness is proven; asking ocx ensure to restore safe persistent routing." Green
    if (-not $DryRun) {
      $ensureExit = Invoke-Ocx @("ensure")
      if ($ensureExit -ne 0) {
        if (-not (Restore-Native)) { exit 1 }
      } else {
        Write-Repair "Codex routing repaired and readiness rechecked." Green
      }
    } else {
      Write-Repair "DRY RUN: would run ocx ensure; no configuration or process will be changed." DarkYellow
    }
  }
} catch {
  Write-Repair "Safe repair failed closed: $($_.Exception.Message)" Red
  if (-not (Restore-Native)) { exit 1 }
  exit 1
} finally {
  if (-not $NoPause) {
    Write-Host ""
    Read-Host "Press Enter to close"
  }
}
