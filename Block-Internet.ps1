# Block-Internet.ps1 (v6)

. "$PSScriptRoot\NetGuard-Common.ps1"

$ruleNameOut = "NetGuard_Block_Outbound"
$ruleNameIn = "NetGuard_Block_Inbound"
$logPath = "C:\ProgramData\NetGuard\block.log"

function Log { param([string]$m) Write-NetGuardLog -LogPath $logPath -Message $m }

# 動規則前先確認防火牆服務活著,以及三個 profile 都是啟用狀態
if (-not (Ensure-FirewallServiceRunning -LogPath $logPath)) {
    Log "因防火牆服務異常而中止封鎖動作"
    exit 1
}
if (-not (Ensure-FirewallProfileEnabled -LogPath $logPath)) {
    Log "因防火牆設定檔異常而中止封鎖動作"
    exit 1
}

try {
    Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    Get-NetFirewallRule -DisplayName $ruleNameIn -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop

    New-NetFirewallRule -Name $ruleNameOut -DisplayName $ruleNameOut `
        -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any `
        -ErrorAction Stop | Out-Null

    New-NetFirewallRule -Name $ruleNameIn -DisplayName $ruleNameIn `
        -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol Any `
        -ErrorAction Stop | Out-Null

    $checkOut = Get-NetFirewallRule -Name $ruleNameOut -ErrorAction Stop
    $checkIn = Get-NetFirewallRule -Name $ruleNameIn -ErrorAction Stop

    # 修正 #8:Enabled 底層是 CIM 包裝型態,不同 PowerShell 版本直接 -eq $true 可能不準,
    # 一律先轉字串再比對,避免版本差異踩雷
    $outOk = ($checkOut.Enabled.ToString() -eq "True") -and ($checkOut.Action.ToString() -eq "Block")
    $inOk = ($checkIn.Enabled.ToString() -eq "True") -and ($checkIn.Action.ToString() -eq "Block")

    if ($outOk -and $inOk) {
        Log "已封鎖網路 (規則建立並驗證成功)"
    } else {
        Log "封鎖規則建立後驗證失敗,狀態異常: Out.Enabled=$($checkOut.Enabled) Out.Action=$($checkOut.Action) In.Enabled=$($checkIn.Enabled) In.Action=$($checkIn.Action)"
        exit 1
    }
}
catch {
    Log "封鎖失敗: $($_.Exception.Message)"
    exit 1
}
