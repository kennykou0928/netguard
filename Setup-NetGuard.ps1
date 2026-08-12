# Setup-NetGuard.ps1 (v6)
# 請以「系統管理員」身分執行:
# .\Setup-NetGuard.ps1 -KidUsername "帳號名稱" [-WebhookUrl "https://discord.com/api/webhooks/..."]

param(
    [Parameter(Mandatory=$true)]
    [string]$KidUsername,

    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl
)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "請以「系統管理員」身分重新開啟 PowerShell 後再執行此腳本。"
    exit 1
}

# 載入共用函式(Invoke-Icacls / Write-NetGuardLog 等),Setup 自己也需要用到
if (-not (Test-Path (Join-Path $PSScriptRoot "NetGuard-Common.ps1"))) {
    Write-Host "找不到 NetGuard-Common.ps1,請確認與 Setup-NetGuard.ps1 放在同一資料夾。"
    exit 1
}
. (Join-Path $PSScriptRoot "NetGuard-Common.ps1")
$setupLogPath = "C:\ProgramData\NetGuard\install.log"

# 修正 P1 #3:從 Discord 複製貼上很容易夾帶看不見的空白/換行字元,
# 先 Trim 再驗證,並印出開頭片段方便你比對是否真的是你貼的那串
if ($WebhookUrl) {
    $WebhookUrl = $WebhookUrl.Trim()
    $preview = if ($WebhookUrl.Length -gt 50) { $WebhookUrl.Substring(0,50) + "..." } else { $WebhookUrl }
    Write-Host "收到的 WebhookUrl(前 50 字元): $preview"

    if ($WebhookUrl -notmatch '^https://discord(app)?\.com/api/webhooks/\d+/[\w-]+$') {
        Write-Host "-WebhookUrl 格式看起來不像合法的 Discord webhook URL,請確認後重試。"
        Write-Host "正確格式範例: https://discord.com/api/webhooks/123456789012345678/AbCdEf..."
        exit 1
    }
}

$installDir = "C:\ProgramData\NetGuard"

$kidUser = Get-LocalUser -Name $KidUsername -ErrorAction SilentlyContinue
if (-not $kidUser) {
    Write-Host "找不到帳號 '$KidUsername',目前本機帳號:"
    Get-LocalUser | Select-Object Name | Format-Table -AutoSize
    exit 1
}

$sourceFiles = @("Block-Internet.ps1", "Unblock-Internet.ps1", "NetGuard-Watchdog.ps1", "NetGuard-Common.ps1", "Lock-Screen.ps1", "NetGuard-Audit.ps1")

$missing = @()
foreach ($f in $sourceFiles) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Host "缺少以下檔案,請確認與 Setup-NetGuard.ps1 放在同一資料夾:"
    $missing | ForEach-Object { Write-Host " - $_" }
    exit 1
}

$taskBlock = "SysNetSvc-4471"
$taskUnblock = "SysNetSvc-4472"
$taskWatchdog = "SysNetSvc-4473"
$taskLock = "SysNetSvc-4474"
$taskAudit = "SysNetSvc-4475"
$allTasks = @($taskBlock, $taskUnblock, $taskWatchdog, $taskLock, $taskAudit)
$allRules = @("NetGuard_Block_Outbound", "NetGuard_Block_Inbound")

# 修正 #2:先拍照「執行本腳本之前」哪些 NetGuard 任務名稱就已經存在(例如你在重跑 Setup 做覆蓋安裝),
# rollback 時只刪「這次新增」的,不要把上一次就裝好、正常運作中的任務也一起清掉
$preExistingTasks = @()
foreach ($t in $allTasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        $preExistingTasks += $t
    }
}

function Invoke-Rollback {
    param([string]$Reason)
    Write-Host ""
    Write-Host "安裝失敗($Reason),正在自動 rollback 這次新增的項目..."
    foreach ($t in @($taskAudit, $taskWatchdog, $taskBlock, $taskUnblock, $taskLock)) {
        if ($preExistingTasks -contains $t) {
            Write-Host " 跳過 '$t':這是本次執行前就已存在的任務,不動它"
            continue
        }
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            try { Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null } catch {}
            try { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            Write-Host " 已移除本次新增的任務: $t"
        }
    }
    # 防火牆規則沒有「這次新增 vs 原本就有」的區分需求(規則本身無害,不像任務會佔用帳號登入邏輯),
    # 但為求乾淨,若本次安裝流程中有建立就一併清掉
    foreach ($r in $allRules) {
        $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        if ($rule) { $rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    }
    Write-Host "Rollback 完成。請排除錯誤原因後重新執行。"
}

if (-not (Test-Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
}

foreach ($f in $sourceFiles) {
    Copy-Item -Path (Join-Path $PSScriptRoot $f) -Destination (Join-Path $installDir $f) -Force
}

if ($WebhookUrl) {
    $configPath = Join-Path $installDir "config.json"
    @{ WebhookUrl = $WebhookUrl } | ConvertTo-Json | Out-File -FilePath $configPath -Encoding utf8 -Force

    # config.json 內含 webhook URL(等同一個可寫入你 Discord 頻道的密鑰),
    # 鎖成只有 SYSTEM/Administrators 可讀,標準使用者不行。
    # 修正 P3:每個 icacls 呼叫都檢查是否真的成功,不再無條件 Out-Null
    $lockOk = $true
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/inheritance:r") -LogPath $setupLogPath -Description "config.json 移除繼承")
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/grant", "SYSTEM:F") -LogPath $setupLogPath -Description "config.json 授權 SYSTEM")
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/grant", "Administrators:F") -LogPath $setupLogPath -Description "config.json 授權 Administrators")

    if ($lockOk) {
        Write-Host "已設定 Discord webhook 通知,並鎖定 config.json 權限"
    } else {
        Write-Host "警告: config.json 權限鎖定過程中有步驟失敗,詳見 $setupLogPath。webhook 仍會運作,但檔案可能未完全鎖定。"
    }
}

$kidSid = $kidUser.SID
$isKidAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.SID -eq $kidSid })
$installLog = Join-Path $installDir "install.log"
"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 安裝時 $KidUsername 權限狀態: $(if ($isKidAdmin) {'Administrator'} else {'Standard User'})" |
    Out-File -FilePath $installLog -Append -Encoding utf8

if ($isKidAdmin) {
    Write-Host "警告:'$KidUsername' 目前仍是系統管理員,NTFS 鎖定套了也無效,已略過。"
    Write-Host " 降級後(Set-AccountType.ps1 -Mode standard)請重跑本腳本套用完整保護。"
} else {
    $folderLockOk = $true
    $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($installDir, "/inheritance:r", "/T") -LogPath $setupLogPath -Description "資料夾移除繼承")
    $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($installDir, "/grant", "SYSTEM:(OI)(CI)F", "/T") -LogPath $setupLogPath -Description "資料夾授權 SYSTEM")
    $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($installDir, "/grant", "Administrators:(OI)(CI)F", "/T") -LogPath $setupLogPath -Description "資料夾授權 Administrators")
    $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($installDir, "/grant", "Authenticated Users:(OI)(CI)RX", "/T") -LogPath $setupLogPath -Description "資料夾授權 Authenticated Users")

    foreach ($f in $sourceFiles) {
        $fp = Join-Path $installDir $f
        $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($fp, "/inheritance:r") -LogPath $setupLogPath -Description "$f 移除繼承")
        $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($fp, "/grant", "SYSTEM:F") -LogPath $setupLogPath -Description "$f 授權 SYSTEM")
        $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($fp, "/grant", "Administrators:F") -LogPath $setupLogPath -Description "$f 授權 Administrators")
        $folderLockOk = $folderLockOk -and (Invoke-Icacls -Arguments @($fp, "/grant", "Authenticated Users:RX") -LogPath $setupLogPath -Description "$f 授權 Authenticated Users")
    }
    # config.json 前面已經鎖過(只給 SYSTEM/Administrators),這裡不動它,
    # 否則會被這段迴圈的 Authenticated Users:RX 覆蓋掉
    if ($folderLockOk) {
        Write-Host "已對 $installDir 及其內容套用 NTFS 鎖定"
    } else {
        Write-Host "警告: NTFS 鎖定過程中有步驟失敗,詳見 $setupLogPath,建議手動用 icacls 檢查 $installDir 的權限"
    }
}

foreach ($t in $allTasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Write-Host "偵測到任務 '$t' 已存在,將覆蓋重建。"
    }
}

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

function Register-NetGuardTask {
    param($TaskName, $Action, $Trigger, $Principal, $Settings)
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
            -Principal $Principal -Settings $Settings -Force -ErrorAction Stop | Out-Null
        $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if (-not $check) { throw "任務建立後查無此任務" }
        return $true
    } catch {
        Write-Host "任務 '$TaskName' 建立失敗: $($_.Exception.Message)"
        return $false
    }
}

$principalSystem = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$actionBlock = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Block-Internet.ps1`""
$triggerBlock = New-ScheduledTaskTrigger -Daily -At 9:00PM
$okBlock = Register-NetGuardTask -TaskName $taskBlock -Action $actionBlock -Trigger $triggerBlock -Principal $principalSystem -Settings $settings
if (-not $okBlock) { Invoke-Rollback -Reason "$taskBlock 建立失敗"; exit 1 }

$actionUnblock = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Unblock-Internet.ps1`""
$triggerUnblock = New-ScheduledTaskTrigger -Daily -At 7:00AM
$okUnblock = Register-NetGuardTask -TaskName $taskUnblock -Action $actionUnblock -Trigger $triggerUnblock -Principal $principalSystem -Settings $settings
if (-not $okUnblock) { Invoke-Rollback -Reason "$taskUnblock 建立失敗"; exit 1 }

$actionWatchdog = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\NetGuard-Watchdog.ps1`""
$triggerWatchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)
$okWatchdog = Register-NetGuardTask -TaskName $taskWatchdog -Action $actionWatchdog -Trigger $triggerWatchdog -Principal $principalSystem -Settings $settings
if (-not $okWatchdog) { Invoke-Rollback -Reason "$taskWatchdog 建立失敗"; exit 1 }

$principalInteractive = New-ScheduledTaskPrincipal -UserId $KidUsername -LogonType Interactive -RunLevel LeastPrivilege
$actionLock = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Lock-Screen.ps1`""
$triggerLock = New-ScheduledTaskTrigger -Daily -At 9:00PM
$okLock = Register-NetGuardTask -TaskName $taskLock -Action $actionLock -Trigger $triggerLock -Principal $principalInteractive -Settings $settings
if (-not $okLock) { Invoke-Rollback -Reason "$taskLock 建立失敗"; exit 1 }

# 修正 #7:主動稽核任務,唯讀、每 5 分鐘跑一次,跟 watchdog 用不同 EventKey,不會互相干擾
$actionAudit = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\NetGuard-Audit.ps1`""
$triggerAudit = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
$okAudit = Register-NetGuardTask -TaskName $taskAudit -Action $actionAudit -Trigger $triggerAudit -Principal $principalSystem -Settings $settings
if (-not $okAudit) { Invoke-Rollback -Reason "$taskAudit 建立失敗"; exit 1 }

Write-Host ""
Write-Host "安裝完成,已建立並驗證 5 個排程任務:"
Write-Host "  $taskBlock -> 21:00 封鎖網路"
Write-Host "  $taskUnblock -> 07:00 恢復網路"
Write-Host "  $taskWatchdog -> 每 1 分鐘檢查,防止手動關閉/竄改規則(異常時主動修復)"
Write-Host "  $taskLock -> 21:00 鎖定畫面(僅在 $KidUsername 於前台登入時觸發)"
Write-Host "  $taskAudit -> 每 5 分鐘唯讀稽核,異常只通知不修復"
Write-Host ""
Write-Host "注意(P2 #6,自我檢查限制):如果 $taskAudit 這個稽核任務本身也被刪掉了,"
Write-Host "  不會有任何機制通知你——本系統沒有『稽核者也被稽核』的自我修復能力。"
Write-Host "  建議偶爾自己手動執行: Get-ScheduledTask -TaskName $taskAudit 確認它還在。"
Write-Host ""
Write-Host "已知限制:"
Write-Host "  - Windows 安全模式開機不會執行一般排程任務,此為系統架構限制,無法用腳本解決"
Write-Host "  - 只要 $KidUsername 仍是系統管理員,他理論上可在工作排程器中找到並停用/刪除以上任務"
Write-Host "  - 若要移除,請執行 Uninstall-NetGuard.ps1"
