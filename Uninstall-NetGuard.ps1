# Uninstall-NetGuard.ps1 (v6)

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "請以「系統管理員」身分重新開啟 PowerShell 後再執行此腳本。"
    exit 1
}

$installDir = "C:\ProgramData\NetGuard"
$rules = @("NetGuard_Block_Outbound", "NetGuard_Block_Inbound")

# audit (4475) 必須排在最前面停用:它是唯讀稽核,每 5 分鐘跑一次,
# 如果卡在 watchdog/block/unblock 已經被刪但 audit 還在跑的空檔被觸發一次,
# 會誤判「排程任務不存在」而發假警報。watchdog (4473) 其次,避免它在移除規則過程中把規則重建回來。
$stopOrder = @("SysNetSvc-4475", "SysNetSvc-4473", "SysNetSvc-4471", "SysNetSvc-4472", "SysNetSvc-4474", "SysNetSvc-4476")

$allOk = $true

foreach ($t in $stopOrder) {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($task) {
        # 先停用,確保就算 Unregister 失敗它也不會再自己跑
        try { Disable-ScheduledTask -TaskName $t -ErrorAction Stop | Out-Null } catch {}
        try {
            Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction Stop
        } catch {
            Write-Host "移除任務 '$t' 失敗: $($_.Exception.Message)"
            $allOk = $false
            continue
        }
        # 修正 #3(b):事後查詢確認真的不存在
        Start-Sleep -Milliseconds 300
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            Write-Host "警告:任務 '$t' 移除後仍查詢得到,請人工確認"
            $allOk = $false
        } else {
            Write-Host "已移除並確認排程任務: $t"
        }
    }
}

foreach ($r in $rules) {
    $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    if ($rule) {
        try {
            $rule | Remove-NetFirewallRule -ErrorAction Stop
        } catch {
            Write-Host "移除防火牆規則 '$r' 失敗: $($_.Exception.Message)"
            $allOk = $false
            continue
        }
        Start-Sleep -Milliseconds 300
        if (Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue) {
            Write-Host "警告:防火牆規則 '$r' 移除後仍查詢得到,請人工確認"
            $allOk = $false
        } else {
            Write-Host "已移除並確認防火牆規則: $r"
        }
    }
}

if (Test-Path $installDir) {
    try {
        Remove-Item -Path $installDir -Recurse -Force -ErrorAction Stop
        if (Test-Path $installDir) {
            Write-Host "警告:目錄 '$installDir' 移除後仍存在,請人工確認(可能有檔案被鎖定)"
            $allOk = $false
        } else {
            Write-Host "已移除並確認安裝目錄: $installDir"
        }
    } catch {
        Write-Host "移除安裝目錄失敗: $($_.Exception.Message)"
        $allOk = $false
    }
}

Write-Host ""
if ($allOk) {
    Write-Host "NetGuard 已完全移除並驗證乾淨。"
} else {
    Write-Host "NetGuard 移除過程中有項目未能驗證成功,請檢查上方警告訊息並手動處理。"
}
Write-Host "提醒:若曾用 Set-AccountType.ps1 將帳號降級為標準使用者,此動作不會自動還原,"
Write-Host "  需要的話請另外執行: .\Set-AccountType.ps1 -Mode admin -Username <帳號>"
