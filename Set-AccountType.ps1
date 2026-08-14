# Set-AccountType.ps1 (v5)
# 用途:管理本機帳號的「系統管理員 / 標準使用者」權限切換 + 帳號清單稽核。
# 重要:此腳本「不會」自動還原 kid 帳號的權限,移除 NetGuard 時記得手動跑。

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("standard", "admin", "status", "audit")]
    [string]$Mode,

    [Parameter(Mandatory=$false)]
    [string]$Username
)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "請以「系統管理員」身分重新開啟 PowerShell 後再執行此腳本。"
    exit 1
}

if ($Mode -eq "audit") {
    Write-Host "目前 Administrators 群組成員:"
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize

    Write-Host ""
    Write-Host "所有本機帳號(含最後登入時間):"

    # 修正 P3:CIM 查詢失敗改成收集後一次彙總警告,不要每個帳號各印一次洗畫面
    $cimWarnings = @()

    $results = Get-LocalUser | ForEach-Object {
        $u = $_
        $lastUse = "N/A"
        try {
            $profile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                Where-Object { $_.SID -eq $u.SID.Value }
            if ($profile -and $profile.LastUseTime) {
                $lastUse = $profile.LastUseTime
            }
        } catch {
            $cimWarnings += $u.Name
        }
        [PSCustomObject]@{
            Name = $u.Name
            Enabled = $u.Enabled
            LastLogon = $lastUse
        }
    }

    $results | Format-Table -AutoSize

    if ($cimWarnings.Count -gt 0) {
        Write-Host "警告:以下 $($cimWarnings.Count) 個帳號查詢最後登入時間時 CIM 查詢失敗,其 LastLogon 顯示 N/A 不代表從未登入: $($cimWarnings -join ', ')"
        Write-Host " (這是 Windows 家用版的已知限制,Win32_UserProfile.LastUseTime 在家用版經常讀不到)"
    }
    exit 0
}

if (-not $Username) {
    Write-Host "此模式需要指定 -Username 參數。"
    exit 1
}

$user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
if (-not $user) {
    Write-Host "找不到帳號 '$Username',目前本機帳號清單:"
    Get-LocalUser | Select-Object Name, Enabled | Format-Table -AutoSize
    exit 1
}

$userSid = $user.SID

function Test-IsAdmin {
    param($Sid)
    $member = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $Sid }
    return [bool]$member
}

function Test-SafeToDowngrade {
    # 核心防呆:在真的移除 $Username 的 admin 權限之前,先確認移除後
    # 「仍有其他已啟用的 Administrator 帳號存在」,避免:
    # (a) Windows 直接拒絕(它本來就不准移除最後一個 admin),或
    # (b) 萬一某個 Windows 版本行為不同、真的降權成功了,結果全家沒人能再用 admin 權限
    # 解 NetGuard、裝軟體、救援系統。
    param($ExcludeSid)

    $otherAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -ne $ExcludeSid } |
        ForEach-Object {
            # Get-LocalGroupMember 回傳的成員不一定能直接查到 Enabled 狀態(可能是內建帳號或群組),
            # 用 Get-LocalUser 反查,查不到就當作不是可用的本機使用者帳號,不列入安全名單
            $sidValue = $_.SID.Value
            $u = Get-LocalUser | Where-Object { $_.SID.Value -eq $sidValue }
            if ($u -and $u.Enabled) { $u }
        }

    return [bool]$otherAdmins
}

switch ($Mode) {
    "status" {
        if (Test-IsAdmin -Sid $userSid) {
            Write-Host "帳號 '$Username' 目前權限: Administrator (系統管理員)"
        } else {
            Write-Host "帳號 '$Username' 目前權限: Standard User (標準使用者)"
        }
    }

    "admin" {
        if (Test-IsAdmin -Sid $userSid) {
            Write-Host "'$Username' 已經是系統管理員,無需變更"
        } else {
            # 修正 #2:補 try/catch + -ErrorAction Stop,失敗時要看得到原因,不能默默不動作
            try {
                Add-LocalGroupMember -Group "Administrators" -Member $userSid.Value -ErrorAction Stop
                Write-Host "已將 '$Username' 加入 Administrators 群組"
            } catch {
                Write-Host "加入 Administrators 群組失敗: $($_.Exception.Message)"
                exit 1
            }
        }
    }

    "standard" {
        if (-not (Test-IsAdmin -Sid $userSid)) {
            Write-Host "'$Username' 已經是標準使用者,無需變更"
        } else {
            # 核心防呆(對應本次要修的漏洞):降權前先確認還有其他啟用中的 admin 帳號,
            # 不然「唯一本機帳號」的機器降權後會被鎖死,家長也進不去
            if (-not (Test-SafeToDowngrade -ExcludeSid $userSid)) {
                Write-Host "拒絕降權:'$Username' 目前是本機唯一啟用中的系統管理員帳號。"
                Write-Host "降權後將沒有任何可用的 admin 路徑,連你自己都無法解除 NetGuard、調整設定或安裝軟體。"
                Write-Host ""
                Write-Host "請先執行以下指令建立備援管理員帳號,再重跑本次降權:"
                Write-Host "  .\New-GuardianAdmin.ps1 -AccountName ""<你自己會記得的帳號名稱>"""
                exit 1
            }

            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $userSid.Value -ErrorAction Stop
                Write-Host "已將 '$Username' 從 Administrators 群組移除,現為標準使用者"
                Write-Host "提醒:"
                Write-Host "  1. 需登出重新登入才會完全生效"
                Write-Host "  2. 降級後請重新執行 Setup-NetGuard.ps1 以套用完整 NTFS 保護"
                Write-Host "  3. 請確保他不知道你的系統管理員密碼"
                Write-Host "  4. 已確認系統上仍有其他啟用中的管理員帳號可供你使用"
            } catch {
                Write-Host "從 Administrators 群組移除失敗: $($_.Exception.Message)"
                Write-Host "常見原因:這是本機唯一剩下的系統管理員帳號,Windows 不允許移除最後一個管理員"
                exit 1
            }
        }
    }
}
