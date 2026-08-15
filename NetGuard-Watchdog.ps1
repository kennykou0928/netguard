# NetGuard-Watchdog.ps1  (v4)

. "$PSScriptRoot\NetGuard-Common.ps1"

$ruleNameOut  = "NetGuard_Block_Outbound"
$ruleNameIn   = "NetGuard_Block_Inbound"
$logPath      = "C:\ProgramData\NetGuard\watchdog.log"
$configPath   = "C:\ProgramData\NetGuard\config.json"

$blockStartHour = 21
$blockEndHour   = 7

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

$now  = Get-Date
$hour = $now.Hour
$shouldBeBlocked = ($hour -ge $blockStartHour) -or ($hour -lt $blockEndHour)

$ruleOut = Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue
$ruleIn  = Get-NetFirewallRule -DisplayName $ruleNameIn  -ErrorAction SilentlyContinue

$outOk = $ruleOut -and ($ruleOut.Enabled.ToString() -eq "True") -and ($ruleOut.Action.ToString() -eq "Block")
$inOk  = $ruleIn  -and ($ruleIn.Enabled.ToString()  -eq "True") -and ($ruleIn.Action.ToString()  -eq "Block")
$currentlyBlocked = $outOk -and $inOk

try {
    if ($shouldBeBlocked -and -not $currentlyBlocked) {
        $tamperType = if (-not $ruleOut -or -not $ruleIn) { "規則被刪除" }
                      else { "規則被停用或 Action 被改成非 Block" }

        # 對應 GPT review should-fix:原本是「先 Remove 兩條規則、再 New 兩條規則」,
        # 中間存在短暫的完全不封鎖空窗。改成:規則存在但狀態不對時用 Set-NetFirewallRule
        # 原地修正(單一 atomic 呼叫,沒有空窗);只有規則整個被刪除時才需要 New-NetFirewallRule。
        if ($ruleOut) {
            $ruleOut | Set-NetFirewallRule -Enabled True -Action Block -ErrorAction Stop
        } else {
            New-NetFirewallRule -Name $ruleNameOut -DisplayName $ruleNameOut `
                -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any `
                -ErrorAction Stop | Out-Null
        }
        if ($ruleIn) {
            $ruleIn | Set-NetFirewallRule -Enabled True -Action Block -ErrorAction Stop
        } else {
            New-NetFirewallRule -Name $ruleNameIn -DisplayName $ruleNameIn `
                -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol Any `
                -ErrorAction Stop | Out-Null
        }

        Log "偵測到封鎖時段內遭竄改($tamperType),已強制修復封鎖規則"
        Send-NetGuardWebhook -ConfigPath $configPath -EventKey "tamper_detected" `
            -Message "偵測到封鎖時段內網路規則遭竄改($tamperType),已自動修復" -LogPath $logPath
    }
    elseif (-not $shouldBeBlocked -and $currentlyBlocked) {
        if ($ruleOut) { $ruleOut | Remove-NetFirewallRule -ErrorAction Stop }
        if ($ruleIn)  { $ruleIn  | Remove-NetFirewallRule -ErrorAction Stop }
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

# 對應 GPT review P0 #3(務實版本):Audit(4475)不檢查自己,單一失效點的疑慮成立。
# 完整的「觀察者的觀察者」在純排程架構下永遠有最後一層沒人看,這裡採取務實做法:
# 補上 Watchdog(4473)反向檢查 Audit(4475)是否還在「並自動重建」的能力。
# 注意:Audit 那邊「偵測 Watchdog 是否還在」的檢查其實原本就有(見 NetGuard-Audit.ps1
# 的 $expectedTasks 陣列已包含 SysNetSvc-4473),所以雙方本來就會互相偵測對方存不存在;
# 這裡新增的只是「Watchdog 這一側」的自動重建能力——Audit 那一側刻意不做自動重建
# (它的設計原則是絕不修改任何規則或服務狀態,只檢查與通知),這是有意的不對稱,不是漏做。
# 攻擊者要讓監控完全消失,現在必須同時刪掉兩個不同編號、不同執行頻率的任務,
# 門檻比刪一個高不少,但仍不是理論完美解——如果兩個同時被刪,還是沒人知道。
$taskAudit  = "SysNetSvc-4475"
$installDir = "C:\ProgramData\NetGuard"

if (-not (Get-ScheduledTask -TaskName $taskAudit -ErrorAction SilentlyContinue)) {
    Log "偵測到稽核任務 '$taskAudit' 不存在,嘗試重新註冊"
    try {
        $auditScriptPath = Join-Path $installDir "NetGuard-Audit.ps1"
        if (-not (Test-Path $auditScriptPath)) {
            throw "找不到 $auditScriptPath,無法重新註冊(腳本本體也遺失,需重新執行 Setup-NetGuard.ps1)"
        }
        $principalSystem = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $auditSettings   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $actionAudit     = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$auditScriptPath`""
        $triggerAudit    = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
        Register-ScheduledTask -TaskName $taskAudit -Action $actionAudit -Trigger $triggerAudit `
            -Principal $principalSystem -Settings $auditSettings -Force -ErrorAction Stop | Out-Null

        Log "已重新註冊稽核任務 '$taskAudit'"
        Send-NetGuardWebhook -ConfigPath $configPath -EventKey "audit_task_missing" `
            -Message "稽核任務 '$taskAudit' 被刪除,Watchdog 已自動補回" -LogPath $logPath
    } catch {
        Log "重新註冊稽核任務失敗: $($_.Exception.Message)"
        Send-NetGuardWebhook -ConfigPath $configPath -EventKey "audit_task_missing" `
            -Message "稽核任務 '$taskAudit' 被刪除且自動補回失敗,監控可能已出現盲區,請盡快人工檢查" -LogPath $logPath
    }
}
