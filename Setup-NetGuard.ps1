# Setup-NetGuard.ps1  (v4)
# 請以「系統管理員」身分執行:
#   .\Setup-NetGuard.ps1 -KidUsername "帳號名稱" [-WebhookUrl "https://discord.com/api/webhooks/..."]

param(
    [Parameter(Mandatory=$true)]
    [string]$KidUsername,

    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl,

    # 對應 GPT review P0 #1:預設拒絕在 kid 仍是 Administrator 的狀態下安裝,
    # 因為 SYSTEM 排程任務執行的是 C:\ProgramData\NetGuard\*.ps1,
    # 如果 kid 還是 admin,他可以直接改這些腳本內容,等於讓 SYSTEM 執行「他寫的程式碼」。
    # 加這個參數只是保留「進階使用者想先裝、之後再降權」的彈性,預設值是 false(即 Hard Fail)。
    [switch]$Force
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

    # 對應 GPT review nitpick:credential 的前綴沒有診斷價值,反而容易被使用者
    # 貼進 issue/log/截圖裡意外外流,改成只確認「有收到」跟「格式驗證結果」
    Write-Host "已收到 Discord Webhook URL(內容已隱藏)"

    if ($WebhookUrl -notmatch '^https://discord(app)?\.com/api/webhooks/\d+/[\w-]+$') {
        Write-Host "-WebhookUrl 格式看起來不像合法的 Discord webhook URL,請確認後重試。"
        Write-Host "正確格式範例: https://discord.com/api/webhooks/123456789012345678/AbCdEf..."
        exit 1
    }
    Write-Host "Discord Webhook URL 格式驗證通過"
}

$installDir = "C:\ProgramData\NetGuard"

$kidUser = Get-LocalUser -Name $KidUsername -ErrorAction SilentlyContinue
if (-not $kidUser) {
    Write-Host "找不到帳號 '$KidUsername',目前本機帳號:"
    Get-LocalUser | Select-Object Name | Format-Table -AutoSize
    exit 1
}

# 對應 GPT review P0 #1(最重要的一項):在做任何安裝動作之前先判斷 kid 是否仍是 Administrator。
# 這不是一般 warning——後面所有 SYSTEM 排程任務執行的都是 C:\ProgramData\NetGuard\*.ps1,
# 如果 kid 還是 admin,他可以直接改這些腳本內容,等於讓 SYSTEM 執行「他寫的程式碼」,
# NTFS 鎖定完全無法防禦這件事(Administrators 群組本來就對這些檔案有完全控制權)。
# 預設 Hard Fail,拒絕在不安全的狀態下安裝;-Force 保留給想先裝、之後再降權的進階使用者。
$kidSid = $kidUser.SID
$isKidAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.SID -eq $kidSid })
$script:UnsafeInstall = $false

if ($isKidAdmin) {
    if (-not $Force) {
        Write-Host "錯誤:'$KidUsername' 目前仍是系統管理員。"
        Write-Host "NetGuard 無法在 Administrator 帳號下建立安全的 NTFS 邊界"
        Write-Host "(SYSTEM 排程任務執行的腳本,admin 帳號本來就有完全控制權可以竄改)。"
        Write-Host ""
        Write-Host "請先執行:"
        Write-Host "  .\Set-AccountType.ps1 -Mode standard -Username `"$KidUsername`""
        Write-Host ""
        Write-Host "如果你確定要先裝、之後再降權,請加上 -Force 參數重新執行本腳本,"
        Write-Host "但在你完成降權並重跑本腳本之前,NetGuard 的所有保護都可被 '$KidUsername' 自行解除。"
        exit 1
    } else {
        $script:UnsafeInstall = $true
        Write-Host "======================================================================"
        Write-Host "  警告:以 -Force 在 '$KidUsername' 仍是系統管理員的狀態下安裝"
        Write-Host "  此次安裝結果將標記為 INSTALLATION INCOMPLETE / UNSAFE"
        Write-Host "  排程任務會建立,但 NTFS 保護無效,'$KidUsername' 可自行竄改或刪除"
        Write-Host "  請盡快執行 Set-AccountType.ps1 -Mode standard 後重跑本腳本補上保護"
        Write-Host "======================================================================"
    }
}

# 軟性提醒(不中止安裝):如果這台機器只有 1 個本機帳號,
# 之後用 Set-AccountType.ps1 降權會被安全檢查擋下來,先讓你知道要先跑 New-GuardianAdmin.ps1
$totalAccounts = (Get-LocalUser | Measure-Object).Count
if ($totalAccounts -le 1) {
    Write-Host "提醒:偵測到本機目前只有 1 個帳號('$KidUsername')。"
    Write-Host "      日後若要用 Set-AccountType.ps1 把 '$KidUsername' 降為標準使用者,"
    Write-Host "      請先執行 New-GuardianAdmin.ps1 建立備援管理員帳號,否則降權會被拒絕。"
}

$sourceFiles = @("Block-Internet.ps1", "Unblock-Internet.ps1", "NetGuard-Watchdog.ps1", "NetGuard-Common.ps1", "Lock-Screen.ps1", "NetGuard-Audit.ps1", "Warn-Bedtime.ps1")

$missing = @()
foreach ($f in $sourceFiles) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Host "缺少以下檔案,請確認與 Setup-NetGuard.ps1 放在同一資料夾:"
    $missing | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

$taskBlock    = "SysNetSvc-4471"
$taskUnblock  = "SysNetSvc-4472"
$taskWatchdog = "SysNetSvc-4473"
$taskLock     = "SysNetSvc-4474"
$taskAudit    = "SysNetSvc-4475"
$taskWarn     = "SysNetSvc-4476"
$allTasks     = @($taskBlock, $taskUnblock, $taskWatchdog, $taskLock, $taskAudit, $taskWarn)
$allRules     = @("NetGuard_Block_Outbound", "NetGuard_Block_Inbound")

# 修正 #2:先拍照「執行本腳本之前」哪些 NetGuard 任務名稱就已經存在(例如你在重跑 Setup 做覆蓋安裝),
# rollback 時只刪「這次新增」的,不要把上一次就裝好、正常運作中的任務也一起清掉
$preExistingTasks = @()
foreach ($t in $allTasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        $preExistingTasks += $t
    }
}

# 對應 GPT review 第二輪 P0-2:防火牆規則比照 Task 的做法,一樣先拍照「執行前是否已存在」。
# 舊版註解寫「規則本身無害」是不夠安全的假設——Setup 明確支援重跑覆蓋安裝,
# 如果 rollback 無差別刪掉所有 NetGuard 規則,會連上一次部署好、正常運作中的規則也一併砍掉。
$preExistingRules = @()
foreach ($r in $allRules) {
    if (Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue) {
        $preExistingRules += $r
    }
}

function Invoke-Rollback {
    param([string]$Reason)
    Write-Host ""
    Write-Host "安裝失敗($Reason),正在自動 rollback 這次新增的項目..."
    foreach ($t in @($taskAudit, $taskWatchdog, $taskBlock, $taskUnblock, $taskLock, $taskWarn)) {
        if ($preExistingTasks -contains $t) {
            Write-Host "  跳過 '$t':這是本次執行前就已存在的任務,不動它"
            continue
        }
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            try { Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null } catch {}
            try { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            Write-Host "  已移除本次新增的任務: $t"
        }
    }

    foreach ($r in $allRules) {
        if ($preExistingRules -contains $r) {
            Write-Host "  跳過防火牆規則 '$r':這是本次執行前就已存在的規則,不動它"
            continue
        }
        $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        if ($rule) {
            $rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Host "  已移除本次新增的防火牆規則: $r"
        }
    }

    # 對應 GPT review 第二輪 P0-1(這輪最重要的一項):舊版 rollback 只清 Task/Rule,
    # 完全沒處理已經寫入磁碟的 config.json(內含 webhook URL,等同一把 Discord 頻道憑證)
    # 跟複製過去的 .ps1 腳本,導致「安裝失敗」的部署反而在磁碟上留下敏感資訊跟半套檔案。
    if (-not $installDirExistedBefore) {
        # 這次是全新安裝(資料夾原本不存在),裡面所有東西都是這次建立的,整個刪乾淨最安全
        if (Test-Path $installDir) {
            try {
                Remove-Item -Path $installDir -Recurse -Force -ErrorAction Stop
                Write-Host "  已移除本次新增的安裝目錄(含 config.json、腳本、log): $installDir"
            } catch {
                Write-Host "  警告:移除安裝目錄失敗,可能仍留有 config.json 等敏感檔案,請手動檢查並刪除 $installDir : $($_.Exception.Message)"
            }
        }
    } elseif (-not $configJsonExistedBefore -and (Test-Path $configPath)) {
        # 這次是覆蓋安裝(資料夾原本就存在,可能是既有正常部署),不能整個資料夾砍掉,
        # 但至少要把「這次新建立」的 config.json 清掉,不留下 webhook 憑證
        try {
            Remove-Item -Path $configPath -Force -ErrorAction Stop
            Write-Host "  已移除本次新增的 config.json(webhook 憑證)"
        } catch {
            Write-Host "  警告:移除 config.json 失敗,可能仍留有 webhook 憑證,請手動檢查並刪除 $configPath : $($_.Exception.Message)"
        }
    }

    Write-Host "Rollback 完成。請排除錯誤原因後重新執行。"
}

$installDirExistedBefore = Test-Path $installDir
$configPath = Join-Path $installDir "config.json"
$configJsonExistedBefore = Test-Path $configPath

if (-not (Test-Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
}

foreach ($f in $sourceFiles) {
    Copy-Item -Path (Join-Path $PSScriptRoot $f) -Destination (Join-Path $installDir $f) -Force
}

if ($WebhookUrl) {
    @{ WebhookUrl = $WebhookUrl } | ConvertTo-Json | Out-File -FilePath $configPath -Encoding utf8 -Force

    # config.json 內含 webhook URL(等同一個可寫入你 Discord 頻道的密鑰),
    # 鎖成只有 SYSTEM/Administrators 可讀,標準使用者不行。
    $lockOk = $true
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/inheritance:r") -LogPath $setupLogPath -Description "config.json 移除繼承")
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/grant", "SYSTEM:F") -LogPath $setupLogPath -Description "config.json 授權 SYSTEM")
    $lockOk = $lockOk -and (Invoke-Icacls -Arguments @($configPath, "/grant", "Administrators:F") -LogPath $setupLogPath -Description "config.json 授權 Administrators")

    # 對應 GPT review P0 #4:config.json 裡的 webhook URL 本質上是一把「可寫入你 Discord 頻道」的
    # 憑證,ACL 鎖定失敗不能只是 warning 後繼續——那等於讓 kid 有機會讀到它、之後可以冒充 NetGuard 發訊息。
    # 這裡直接視為安裝失敗:要嘛乾淨鎖住,要嘛整個 rollback,不要留下「webhook 能用但沒鎖好」的中間態。
    if ($lockOk) {
        Write-Host "已設定 Discord webhook 通知,並鎖定 config.json 權限"
    } else {
        Invoke-Rollback -Reason "config.json 權限鎖定失敗,webhook URL 可能被 '$KidUsername' 讀取"
        exit 1
    }
}

$installLog = Join-Path $installDir "install.log"
"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  安裝時 $KidUsername 權限狀態: $(if ($isKidAdmin) {'Administrator'} else {'Standard User'})$(if ($script:UnsafeInstall) {' (使用 -Force,UNSAFE)'})" |
    Out-File -FilePath $installLog -Append -Encoding utf8

if ($isKidAdmin) {
    Write-Host "警告:'$KidUsername' 目前仍是系統管理員,NTFS 鎖定套了也無效,已略過(-Force 模式)。"
    Write-Host "         降級後(Set-AccountType.ps1 -Mode standard)請重跑本腳本套用完整保護。"
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

    # 對應 GPT review P0 #2:NTFS 鎖定失敗不能只是 warning 後繼續建立 SYSTEM 排程任務——
    # 那會產生「SYSTEM 執行 kid 可寫入的腳本」這種比 kid 是 admin 更難察覺的危險狀態
    # (因為畫面上會顯示「已降為標準使用者」,看起來是安全的,實際上鎖定沒生效)。
    if ($folderLockOk) {
        Write-Host "已對 $installDir 及其內容套用 NTFS 鎖定"
    } else {
        Invoke-Rollback -Reason "NTFS 權限鎖定失敗,'$KidUsername' 可能仍可寫入 NetGuard 腳本"
        exit 1
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

$actionBlock  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Block-Internet.ps1`""
$triggerBlock = New-ScheduledTaskTrigger -Daily -At 9:00PM
$okBlock = Register-NetGuardTask -TaskName $taskBlock -Action $actionBlock -Trigger $triggerBlock -Principal $principalSystem -Settings $settings
if (-not $okBlock) { Invoke-Rollback -Reason "$taskBlock 建立失敗"; exit 1 }

$actionUnblock  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Unblock-Internet.ps1`""
$triggerUnblock = New-ScheduledTaskTrigger -Daily -At 7:00AM
$okUnblock = Register-NetGuardTask -TaskName $taskUnblock -Action $actionUnblock -Trigger $triggerUnblock -Principal $principalSystem -Settings $settings
if (-not $okUnblock) { Invoke-Rollback -Reason "$taskUnblock 建立失敗"; exit 1 }

$actionWatchdog  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\NetGuard-Watchdog.ps1`""
$triggerWatchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)
$okWatchdog = Register-NetGuardTask -TaskName $taskWatchdog -Action $actionWatchdog -Trigger $triggerWatchdog -Principal $principalSystem -Settings $settings
if (-not $okWatchdog) { Invoke-Rollback -Reason "$taskWatchdog 建立失敗"; exit 1 }

$principalInteractive = New-ScheduledTaskPrincipal -UserId $KidUsername -LogonType Interactive -RunLevel LeastPrivilege
$actionLock  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Lock-Screen.ps1`""
$triggerLock = New-ScheduledTaskTrigger -Daily -At 9:00PM
$okLock = Register-NetGuardTask -TaskName $taskLock -Action $actionLock -Trigger $triggerLock -Principal $principalInteractive -Settings $settings
if (-not $okLock) { Invoke-Rollback -Reason "$taskLock 建立失敗"; exit 1 }

# 修正 #7:主動稽核任務,唯讀、每 5 分鐘跑一次,跟 watchdog 用不同 EventKey,不會互相干擾
$actionAudit  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\NetGuard-Audit.ps1`""
$triggerAudit = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
$okAudit = Register-NetGuardTask -TaskName $taskAudit -Action $actionAudit -Trigger $triggerAudit -Principal $principalSystem -Settings $settings
if (-not $okAudit) { Invoke-Rollback -Reason "$taskAudit 建立失敗"; exit 1 }

# 20:50 睡前提醒(Interactive,同帳號、同邏輯,只是時間點更早、動作更溫和)
$actionWarn  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\Warn-Bedtime.ps1`""
$triggerWarn = New-ScheduledTaskTrigger -Daily -At 8:50PM
$okWarn = Register-NetGuardTask -TaskName $taskWarn -Action $actionWarn -Trigger $triggerWarn -Principal $principalInteractive -Settings $settings
if (-not $okWarn) { Invoke-Rollback -Reason "$taskWarn 建立失敗"; exit 1 }

Write-Host ""
if ($script:UnsafeInstall) {
    Write-Host "======================================================================"
    Write-Host "  安裝完成,但狀態為:INSTALLATION INCOMPLETE / UNSAFE"
    Write-Host "  原因:'$KidUsername' 仍是系統管理員,NTFS 保護未生效"
    Write-Host "  排程任務都已建立,但 '$KidUsername' 目前可自行修改/刪除下列任何一項"
    Write-Host "  請盡快執行:"
    Write-Host "    .\Set-AccountType.ps1 -Mode standard -Username `"$KidUsername`""
    Write-Host "    .\Setup-NetGuard.ps1 -KidUsername `"$KidUsername`" -Force"
    Write-Host "  (第二次執行時 '$KidUsername' 若已是 Standard User,就不需要 -Force,也會補上 NTFS 保護)"
    Write-Host "======================================================================"
} else {
    Write-Host "安裝完成,已建立並驗證 6 個排程任務:"
}
Write-Host "  $taskWarn     -> 20:50 跳出睡前提醒訊息"
Write-Host "  $taskBlock    -> 21:00 封鎖網路"
Write-Host "  $taskUnblock  -> 07:00 恢復網路"
Write-Host "  $taskWatchdog -> 每 1 分鐘檢查,防止手動關閉/竄改規則(異常時主動修復,並會補回被刪除的 $taskAudit)"
Write-Host "  $taskLock     -> 21:00 鎖定畫面(僅在 $KidUsername 於前台登入時觸發)"
Write-Host "  $taskAudit    -> 每 5 分鐘唯讀稽核,異常只通知不修復"
Write-Host ""
Write-Host "關於自我檢查(對應 GPT review P0):$taskWatchdog 跟 $taskAudit 會互相確認對方的排程任務是否還在——"
Write-Host "      Audit 每 5 分鐘的稽核清單本來就包含 $taskWatchdog,Watchdog 這輪新增了反向檢查 $taskAudit。"
Write-Host "      但修復能力不對稱:Watchdog 發現 $taskAudit 消失時會自動重新註冊補回,"
Write-Host "      Audit 發現 $taskWatchdog 消失時只會發送通知、不會自動重建"
Write-Host "      (這是刻意設計——Audit 對自己的定位是『絕不修改任何規則或服務狀態』,只檢查與通知)。"
Write-Host "      這降低了『兩個都被同時刪掉才會失效』的風險,但仍不是理論上完美的解法,"
Write-Host "      建議偶爾自己手動執行: Get-ScheduledTask -TaskName $taskAudit,$taskWatchdog 確認都還在。"
Write-Host ""
Write-Host "已知限制:"
Write-Host "  - Windows 安全模式開機不會執行一般排程任務,此為系統架構限制,無法用腳本解決"
Write-Host "  - 只要 $KidUsername 仍是系統管理員,他理論上可在工作排程器中找到並停用/刪除以上任務"
Write-Host "  - Block-Internet.ps1 建立的是全機層級的防火牆規則(Any Profile),不是只針對 $KidUsername 帳號,"
Write-Host "    這台機器上其他需要夜間網路的服務(Windows Update、備份、遠端管理等)在封鎖時段內也會一併受影響"
Write-Host "  - 若要移除,請執行 Uninstall-NetGuard.ps1"
