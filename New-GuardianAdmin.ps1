# New-GuardianAdmin.ps1
# 用途:在只有 1 個本機帳號的機器上,建立第二個系統管理員帳號給家長使用,
#       確保之後用 Set-AccountType.ps1 把小孩帳號降為 Standard User 時,
#       系統仍有可用的 admin 路徑(否則會被 Windows 拒絕降權,或更糟地失去 admin 存取)。
#
# 重要(誠實聲明,別誤解這支腳本的安全模型):
#   HideUser 只會讓帳號不出現在「歡迎畫面 / 其他使用者」清單,
#   Standard User 帳號依然可以用 `net user` 或 `Get-LocalUser` 在命令列看到帳號名稱。
#   真正的安全邊界是「密碼強度」+「不告訴小孩密碼」,不是帳號名稱保密。
#   請務必設定夠強的密碼,並且不要用「Admin」「Parent」這類完全等於角色名稱的帳號名稱——真正的防線是密碼強度,不是帳號名稱的隱晦程度。
#
# 用法:
#   .\New-GuardianAdmin.ps1 -AccountName "SvcMaintUser"
#   (不加 -Password 會用互動方式安全輸入,不會出現在螢幕或歷史紀錄)

param(
    [Parameter(Mandatory=$true)]
    [string]$AccountName,

    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]$Password
)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "請以「系統管理員」身分重新開啟 PowerShell 後再執行此腳本。"
    exit 1
}

if ($AccountName -match '(?i)^admin$|^administrator$|^parent$') {
    Write-Host "提醒:'$AccountName' 這種完全等於角色名稱的帳號名,孩子在畫面上第一眼就會猜到用途。"
    Write-Host "如果你會記得住,用你自己好記的名字完全沒問題——真正的防線是密碼強度,不是帳號名稱的隱晦程度。"
}

if (-not $Password) {
    Write-Host "請輸入新管理員帳號的密碼(建議 14 碼以上,混合大小寫/數字/符號,且孩子猜不到):"
    $Password = Read-Host -AsSecureString
    Write-Host "請再輸入一次以確認:"
    $confirm = Read-Host -AsSecureString
    $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
    if ($p1 -ne $p2) {
        Write-Host "兩次輸入的密碼不一致,請重新執行。"
        exit 1
    }
    if ($p1.Length -lt 14) {
        Write-Host "密碼長度不足 14 碼,基於這個帳號是唯一的救援路徑,強烈建議加長。"
        exit 1
    }
}

# 冪等性:帳號已存在就檢查/修正狀態,而不是報錯中止
$existing = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue

if (-not $existing) {
    try {
        New-LocalUser -Name $AccountName -Password $Password -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
        Write-Host "已建立帳號 '$AccountName'"
    } catch {
        Write-Host "建立帳號失敗: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "帳號 '$AccountName' 已存在,檢查並修正其狀態..."
    if (-not $existing.Enabled) {
        Enable-LocalUser -Name $AccountName
        Write-Host "  已將帳號從停用改為啟用"
    }
}

# 確保是 Administrators 成員(用 SID 比對避免特殊字元誤判)
$user = Get-LocalUser -Name $AccountName
$isAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.SID -eq $user.SID })
if (-not $isAdmin) {
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $user.SID.Value -ErrorAction Stop
        Write-Host "已將 '$AccountName' 加入 Administrators 群組"
    } catch {
        Write-Host "加入 Administrators 群組失敗: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "'$AccountName' 已經是系統管理員"
}

# 從歡迎畫面隱藏(HideUser),僅止於「不要讓孩子不小心點到」,不是真正的保密機制
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $AccountName -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    Write-Host "已從歡迎畫面隱藏 '$AccountName'(僅防止誤點,不是真正的存取控制)"
} catch {
    Write-Host "設定隱藏帳號失敗(不影響帳號本身能用,只是還會出現在歡迎畫面): $($_.Exception.Message)"
}

Write-Host ""
Write-Host "完成。驗證方式:"
Write-Host "  Get-LocalGroupMember -Group Administrators"
Write-Host ""
Write-Host "建議:把 '$AccountName' 這個帳號名稱記在你自己會記得的地方(密碼管理器備註最好),"
Write-Host "密碼用密碼管理器存,不要跟帳號名稱寫在同一份紙本文件上。"
Write-Host "帳號名稱本身不是防線,你記不住反而讓這個備援帳號形同虛設,密碼夠強、孩子不知道密碼才是重點。"
