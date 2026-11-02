<#
.SYNOPSIS
    Gracefully stops the PhishGuard VirtualBox Analysis Sandbox VM.
#>

param(
    [string]$VmName = "PhishGuard-Analysis-VM",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
)

Write-Host "Gracefully stopping PhishGuard Sandbox VM '$VmName'..." -ForegroundColor Yellow
& "$VBoxManage" controlvm $VmName acpipowerbutton
if ($LASTEXITCODE -eq 0) {
    Write-Host "[SUCCESS] ACPI shutdown signal sent to VM." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Could not stop VM." -ForegroundColor Red
}
