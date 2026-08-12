# NetGuard-Watchdog.ps1 (v6)

. "$PSScriptRoot\NetGuard-Common.ps1"

$ruleNameOut = "NetGuard_Block_Outbound"
$ruleNameIn = "NetGuard_Block_Inbound"
$logPath = "C:\ProgramData\NetGuard\watchdog.log"
$configPath = "C:\ProgramData\NetGuard\config.json"

$blockStartHour = 21
$blockEndHour = 7

function Log { param([string]$m) Write-NetGuardLog -LogPath $logPath -Message $m }

# watchdog 本身也要先確認防火牆服務活著、且三個 profile 都啟用,不然重建規則也是白做
if (-not (Ensure-FirewallServiceRunning -LogPath $logPath)) {
    Send-NetGuardWebhook -ConfigPath $configPath -EventKey "firewall_service_down" `
        -Message "Windows Firewall 服務異常且無法自動啟動,NetGuard 防護可能已完全失效,請盡快檢查" -LogPath $logPath
    exit 1
}
if (-not (Ensure-FirewallProfileEnabled -LogPath $logPath)) {
    Send-NetGuardWebhook -ConfigPath $configPath -EventKey "firewall_profile_disabled" `
        -Message "防火牆設定檔(Domain/Private/Public)遭停用且無法自動修復,規則本身正常但不會生效,請盡快檢查" -LogPath $logPath
    exit 1
}

$now = Get-Date
$hour = $now.Hour
$shouldBeBlocked = ($hour -ge $blockStartHour) -or ($hour -lt $blockEndHour)

$ruleOut = Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue
$ruleIn = Get-NetFirewallRule -DisplayName $ruleNameIn -ErrorAction SilentlyContinue

$outOk = $ruleOut -and ($ruleOut.Enabled.ToString() -eq "True") -and ($ruleOut.Action.ToString() -eq "Block")
$inOk = $ruleIn -and ($ruleIn.Enabled.ToString() -eq "True") -and ($ruleIn.Action.ToString() -eq "Block")
$currentlyBlocked = $outOk -and $inOk

try {
    if ($shouldBeBlocked -and -not $currentlyBlocked) {
        # 修正 #4:$currentlyBlocked 已經等於 $outOk -and $inOk,
        # 所以「規則存在但 outOk/inOk 皆為真」這個分支邏輯上不可能發生,
        # 只需要兩種情況:規則不存在,或規則存在但狀態不對(停用/Action 不是 Block)
        $tamperType = if (-not $ruleOut -or -not $ruleIn) { "規則被刪除" }
        else { "規則被停用或 Action 被改成非 Block" }

        if ($ruleOut) { $ruleOut | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        if ($ruleIn) { $ruleIn | Remove-NetFirewallRule -ErrorAction SilentlyContinue }

        New-NetFirewallRule -Name $ruleNameOut -DisplayName $ruleNameOut `
            -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any `
            -ErrorAction Stop | Out-Null
        New-NetFirewallRule -Name $ruleNameIn -DisplayName $ruleNameIn `
            -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol Any `
            -ErrorAction Stop | Out-Null

        Log "偵測到封鎖時段內遭竄改($tamperType),已強制重建封鎖規則"
        Send-NetGuardWebhook -ConfigPath $configPath -EventKey "tamper_detected" `
            -Message "偵測到封鎖時段內網路規則遭竄改($tamperType),已自動修復" -LogPath $logPath
    }
    elseif (-not $shouldBeBlocked -and $currentlyBlocked) {
        if ($ruleOut) { $ruleOut | Remove-NetFirewallRule -ErrorAction Stop }
        if ($ruleIn) { $ruleIn | Remove-NetFirewallRule -ErrorAction Stop }
        Log "非封鎖時段但規則仍存在,已移除(保險機制觸發)"
    }
    else {
        # 修正 P3:狀態完全正常時歸零 tamper_detected 的 occurrence 計數,
        # 避免長期運作下「(第 5460 次通知)」這種失真的累計數字誤導判讀
        Reset-NetGuardOccurrence -ConfigPath $configPath -EventKey "tamper_detected"
    }
}
catch {
    Log "Watchdog 執行錯誤: $($_.Exception.Message)"
}

# 附註(#7 架構討論):本 watchdog 是被動防禦,只在偵測到異常時動作。
# 若需要主動稽核(定期回報目前狀態是否正常,而不等異常發生才通知),
# 請參考同資料夾的 NetGuard-Audit.ps1(唯讀,不修改任何規則,獨立 throttle key 避免衝突)。
