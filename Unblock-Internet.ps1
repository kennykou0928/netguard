# Unblock-Internet.ps1  (v4)

. "$PSScriptRoot\NetGuard-Common.ps1"

$ruleNameOut = "NetGuard_Block_Outbound"
$ruleNameIn  = "NetGuard_Block_Inbound"
$logPath     = "C:\ProgramData\NetGuard\unblock.log"

function Log { param([string]$m) Write-NetGuardLog -LogPath $logPath -Message $m }

if (-not (Ensure-FirewallServiceRunning -LogPath $logPath)) {
    Log "因防火牆服務異常而中止解除封鎖動作(規則可能仍殘留,請人工確認)"
    exit 1
}
# 解除封鎖不因 profile 被停用而中止(那本來就是「更不封鎖」的方向,不影響解除封鎖的目的),
# 但仍檢查並記錄,方便你知道發生過這件事
Ensure-FirewallProfileEnabled -LogPath $logPath | Out-Null

$errors = @()

$ruleOut = Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue
if ($ruleOut) {
    try { $ruleOut | Remove-NetFirewallRule -ErrorAction Stop }
    catch { $errors += "Outbound 規則移除失敗: $($_.Exception.Message)" }
}

$ruleIn = Get-NetFirewallRule -DisplayName $ruleNameIn -ErrorAction SilentlyContinue
if ($ruleIn) {
    try { $ruleIn | Remove-NetFirewallRule -ErrorAction Stop }
    catch { $errors += "Inbound 規則移除失敗: $($_.Exception.Message)" }
}

if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Log $e }
    exit 1
} elseif (-not $ruleOut -and -not $ruleIn) {
    Log "已恢復網路 (原本就沒有封鎖規則,無需移除)"
} else {
    Log "已恢復網路 (規則移除成功)"
}
