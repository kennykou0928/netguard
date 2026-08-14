# Verify-AdminAccess.ps1
# 用途:唯讀結構性驗證,對應 review 要求的「pytest 式」驗收。
#       不會修改任何帳號/群組狀態,只檢查、只回報,適合在改動後每次重跑當驗收。
# 用法:
#   .\Verify-AdminAccess.ps1 -KidUsername "kid_account"
# Exit code:0 = 全部通過,1 = 有任一項失敗(方便串進其他自動化流程判斷)

param(
    [Parameter(Mandatory=$true)]
    [string]$KidUsername
)

$results = @()

function Add-Result {
    param([string]$Check, [bool]$Pass, [string]$Detail)
    $script:results += [PSCustomObject]@{ Check = $Check; Pass = $Pass; Detail = $Detail }
}

# 1. kid 帳號存在且為 Standard User(不在 Administrators 群組)
$kidUser = Get-LocalUser -Name $KidUsername -ErrorAction SilentlyContinue
if (-not $kidUser) {
    Add-Result -Check "kid 帳號存在" -Pass $false -Detail "找不到帳號 '$KidUsername'"
} else {
    Add-Result -Check "kid 帳號存在" -Pass $true -Detail "SID=$($kidUser.SID.Value)"

    $kidIsAdmin = [bool](Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $kidUser.SID })
    Add-Result -Check "kid 帳號為 Standard User(不在 Administrators)" -Pass (-not $kidIsAdmin) `
        -Detail $(if ($kidIsAdmin) { "仍是系統管理員,NetGuard 排程任務未受 NTFS 保護" } else { "已確認為標準使用者" })
}

# 2. 至少存在 1 個「非 kid」且已啟用的 Administrator 帳號(核心防呆項目)
$otherEnabledAdmins = @()
if ($kidUser) {
    $otherEnabledAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -ne $kidUser.SID } |
        ForEach-Object {
            $sidValue = $_.SID.Value
            Get-LocalUser | Where-Object { $_.SID.Value -eq $sidValue -and $_.Enabled }
        }
}
Add-Result -Check "存在其他已啟用的備援管理員帳號" -Pass ([bool]$otherEnabledAdmins) `
    -Detail $(if ($otherEnabledAdmins) { "備援帳號: $(($otherEnabledAdmins | ForEach-Object { $_.Name }) -join ', ')" } else { "沒有找到任何備援 admin,降權後會被鎖死" })

# 3. 備援帳號密碼未過期、帳號未過期、未被停用(避免「有帳號但登不進去」的假通過)
foreach ($admin in $otherEnabledAdmins) {
    $ok = $admin.Enabled -and (-not $admin.PasswordExpires -or $admin.PasswordExpires -gt (Get-Date))
    Add-Result -Check "備援帳號 '$($admin.Name)' 可正常登入(未過期/未停用)" -Pass $ok `
        -Detail "Enabled=$($admin.Enabled), PasswordExpires=$($admin.PasswordExpires)"
}

# 4. NetGuard 排程任務都存在(結構性檢查,不代表邏輯正確,只確認沒被整組刪除)
$expectedTasks = @("SysNetSvc-4471", "SysNetSvc-4472", "SysNetSvc-4473", "SysNetSvc-4474", "SysNetSvc-4475", "SysNetSvc-4476")
$missingTasks = @()
foreach ($t in $expectedTasks) {
    if (-not (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue)) {
        $missingTasks += $t
    }
}
Add-Result -Check "NetGuard 排程任務完整(6 個)" -Pass ($missingTasks.Count -eq 0) `
    -Detail $(if ($missingTasks.Count -gt 0) { "缺少: $($missingTasks -join ', ')" } else { "全部存在" })

# 5. NetGuard 安裝目錄 NTFS 權限:kid 只能讀執行,不能寫入/刪除(僅在 kid 已是 Standard User 時才有意義)
if ($kidUser -and -not $kidIsAdmin) {
    $installDir = "C:\ProgramData\NetGuard"
    if (Test-Path $installDir) {
        $acl = Get-Acl $installDir
        $kidAccessRules = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match [regex]::Escape($KidUsername) -or
            $_.IdentityReference.Value -eq "Authenticated Users" -or
            $_.IdentityReference.Value -eq "Users"
        }
        $hasWriteOrModify = $kidAccessRules | Where-Object {
            $_.FileSystemRights -match "Write|Modify|FullControl" -and $_.AccessControlType -eq "Allow"
        }
        Add-Result -Check "NetGuard 安裝目錄 kid 無寫入權限" -Pass (-not [bool]$hasWriteOrModify) `
            -Detail $(if ($hasWriteOrModify) { "偵測到可能的寫入權限,請人工複查 icacls 輸出" } else { "未偵測到寫入/完全控制權限" })
    } else {
        Add-Result -Check "NetGuard 安裝目錄 kid 無寫入權限" -Pass $false -Detail "找不到 $installDir,可能尚未執行 Setup-NetGuard.ps1"
    }
}

# --- 輸出結果 ---
Write-Host ""
Write-Host "===== Verify-AdminAccess 驗證結果 ====="
$results | ForEach-Object {
    $mark = if ($_.Pass) { "PASS" } else { "FAIL" }
    Write-Host ("[{0}] {1} - {2}" -f $mark, $_.Check, $_.Detail)
}

$failCount = ($results | Where-Object { -not $_.Pass }).Count
Write-Host ""
if ($failCount -eq 0) {
    Write-Host "全部 $($results.Count) 項通過。"
    exit 0
} else {
    Write-Host "$failCount / $($results.Count) 項失敗,請根據上面訊息排除。"
    exit 1
}
