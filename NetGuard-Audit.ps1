# NetGuard-Audit.ps1 (v6)
# 由 SYSTEM 排程每 5 分鐘觸發。與 NetGuard-Watchdog.ps1 的差異:
#  - Watchdog:偵測到封鎖時段內異常「立即修復」,是主動防禦手段
#  - Audit :只檢查、只記錄、只通知,「絕不修改」任何規則或服務狀態,
# 純粹讓你知道現在整體健康狀態,兩者用不同 EventKey 送 webhook,
# 彼此的 throttle 互不影響,也不會搶著修同一個東西打架。

. "$PSScriptRoot\NetGuard-Common.ps1"

$ruleNameOut = "NetGuard_Block_Outbound"
$ruleNameIn = "NetGuard_Block_Inbound"
$logPath = "C:\ProgramData\NetGuard\audit.log"
$configPath = "C:\ProgramData\NetGuard\config.json"

$blockStartHour = 21
$blockEndHour = 7

function Log { param([string]$m) Write-NetGuardLog -LogPath $logPath -Message $m }

$anomalies = @()

# 1. 服務狀態(唯讀查詢,不呼叫 Ensure-* 系列去嘗試修復)
$svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
if (-not $svc) {
    $anomalies += "找不到 Windows Firewall 服務 (mpssvc)"
} elseif ($svc.Status -ne "Running") {
    $anomalies += "Windows Firewall 服務未執行(狀態=$($svc.Status))"
}

# 2. Profile 狀態
try {
    $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
    $disabledProfiles = $profiles | Where-Object { $_.Enabled -eq $false -or $_.Enabled.ToString() -eq "False" }
    if ($disabledProfiles) {
        $anomalies += "防火牆設定檔已停用: $(($disabledProfiles | ForEach-Object { $_.Name }) -join ', ')"
    }
} catch {
    $anomalies += "查詢防火牆設定檔失敗: $($_.Exception.Message)"
}

# 3. 規則狀態(只在應該封鎖的時段內檢查,非封鎖時段規則本來就該不在,不算異常)
$now = Get-Date
$hour = $now.Hour
$shouldBeBlocked = ($hour -ge $blockStartHour) -or ($hour -lt $blockEndHour)

if ($shouldBeBlocked) {
    $ruleOut = Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue
    $ruleIn = Get-NetFirewallRule -DisplayName $ruleNameIn -ErrorAction SilentlyContinue
    $outOk = $ruleOut -and ($ruleOut.Enabled.ToString() -eq "True") -and ($ruleOut.Action.ToString() -eq "Block")
    $inOk = $ruleIn -and ($ruleIn.Enabled.ToString() -eq "True") -and ($ruleIn.Action.ToString() -eq "Block")
    if (-not ($outOk -and $inOk)) {
        $anomalies += "封鎖時段內防火牆規則異常(預期由 watchdog 於 1 分鐘內修復,若持續出現請檢查 watchdog.log)"
    }
}

# 4. 排程任務本身是否都還在(kid 有沒有整組刪掉)
$expectedTasks = @("SysNetSvc-4471", "SysNetSvc-4472", "SysNetSvc-4473", "SysNetSvc-4474", "SysNetSvc-4476")
foreach ($t in $expectedTasks) {
    if (-not (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue)) {
        $anomalies += "排程任務 '$t' 不存在(可能被刪除)"
    }
}

if ($anomalies.Count -gt 0) {
    $summary = $anomalies -join "; "
    Log "稽核發現異常: $summary"
    # 用獨立 EventKey,跟 Watchdog 的 tamper_detected / firewall_service_down 等分開 throttle
    Send-NetGuardWebhook -ConfigPath $configPath -EventKey "audit_anomaly" `
        -Message "定期稽核發現異常: $summary" -LogPath $logPath
} else {
    # 修正 P2 #4:問題解除了,清掉「連續第 N 次」的計數,下次重新從第 1 次算
    Reset-NetGuardOccurrence -ConfigPath $configPath -EventKey "audit_anomaly"

    # 修正 P2 #5:完全正常時原本不寫 log 會讓人無法確認「稽核真的有在跑」還是「任務已經死了」,
    # 改成每天寫一次心跳,用 heartbeat 檔案記錄日期避免每 5 分鐘洗版
    $heartbeatFile = "C:\ProgramData\NetGuard\audit_heartbeat.txt"
    $today = (Get-Date).ToString("yyyy-MM-dd")
    $lastHeartbeatDate = $null
    if (Test-Path $heartbeatFile) {
        $lastHeartbeatDate = (Get-Content $heartbeatFile -Raw).Trim()
    }
    if ($lastHeartbeatDate -ne $today) {
        Log "稽核系統正常運作中(每日心跳,今日首次成功檢查)"
        $today | Out-File -FilePath $heartbeatFile -Encoding utf8 -Force
    }
}
