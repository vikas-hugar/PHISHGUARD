<#
.SYNOPSIS
    Starts the PhishGuard VirtualBox Analysis Sandbox VM and waits until the agent is healthy.
#>

param(
    [string]$VmName = "PhishGuard-Analysis-VM",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [string]$AgentUrl = "http://192.168.56.101:8765/health",
    [int]$TimeoutSeconds = 45
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PhishGuard AI - VirtualBox Sandbox Startup Manager     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check if VBoxManage exists
if (-not (Test-Path $VBoxManage)) {
    Write-Host "[ERROR] VBoxManage not found at: $VBoxManage" -ForegroundColor Red
    exit 1
}

# 2. Check VM State
Write-Host "[1/3] Checking state of VM '$VmName'..." -ForegroundColor Yellow
$infoLines = & "$VBoxManage" showvminfo $VmName --machinereadable 2>&1
$isVmRunning = $false
foreach ($line in $infoLines) {
    if ($line -like '*VMState="running"*') {
        $isVmRunning = $true
        break
    }
}

if ($isVmRunning) {
    Write-Host "      VM is already running." -ForegroundColor Green
} else {
    Write-Host "      Powering on VM (headless mode)..." -ForegroundColor Yellow
    $startResult = & "$VBoxManage" startvm $VmName --type headless 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to start VM: $startResult" -ForegroundColor Red
        exit 1
    }
    Write-Host "      VM powered on successfully." -ForegroundColor Green
}

# 3. Wait for Sandbox Agent to respond
Write-Host "[2/3] Waiting for Linux guest & analysis agent to initialize on $AgentUrl..." -ForegroundColor Yellow
$elapsed = 0
$interval = 2
$isReady = $false
$agentJson = ""

while ($elapsed -lt $TimeoutSeconds) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval

    try {
        $res = curl.exe -s --connect-timeout 1 -m 2 $AgentUrl 2>$null
        if ($res -and ($res -like '*"available":true*')) {
            $isReady = $true
            $agentJson = $res
            break
        }
    } catch {
        # continue loop
    }
    Write-Host "      Waiting for boot... ($elapsed seconds elapsed)" -ForegroundColor DarkGray
}

# 4. Result
Write-Host "----------------------------------------------------------" -ForegroundColor Cyan
if ($isReady) {
    Write-Host "[SUCCESS] Sandbox VM is ONLINE and HEALTHY in $elapsed seconds!" -ForegroundColor Green
    Write-Host "Response: $agentJson" -ForegroundColor Gray
} else {
    Write-Host "[WARNING] Sandbox VM started, but agent did not report healthy within $TimeoutSeconds seconds." -ForegroundColor Red
    Write-Host "You can test connectivity manually with: curl.exe $AgentUrl" -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
