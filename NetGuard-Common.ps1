# NetGuard-Common.ps1 (v6)
# 共用函式庫,被其他 4 個腳本 dot-source 載入。
# 注意:每個函式都不會 exit 1,只 return $true/$false,由呼叫端決定如何處理。

$script:NetGuardLogMaxBytes = 1MB
$script:NetGuardThrottleWindowMinutes = 5

function Write-NetGuardLog {
    param(
        [Parameter(Mandatory=$true)][string]$LogPath,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # 修正 #7:保留 2 份歷史(.1 較新、.2 較舊),超過就淘汰最舊的一份
    if (Test-Path $LogPath) {
        $size = (Get-Item $LogPath).Length
        if ($size -ge $script:NetGuardLogMaxBytes) {
            $p2 = "$LogPath.2"
            $p1 = "$LogPath.1"
            if (Test-Path $p2) { Remove-Item $p2 -Force }
            if (Test-Path $p1) { Rename-Item -Path $p1 -NewName (Split-Path $p2 -Leaf) -Force }
            Rename-Item -Path $LogPath -NewName (Split-Path $p1 -Leaf) -Force
        }
    }

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8
}

function Invoke-Icacls {
    # 修正 P3:icacls 是外部執行檔,呼叫失敗不會拋 PowerShell 例外,
    # 之前的寫法直接 Out-Null 等於完全不管成功與否。改成統一檢查 $LASTEXITCODE。
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$LogPath,
        [string]$Description = "icacls 操作"
    )
    try {
        $output = & icacls @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-NetGuardLog -LogPath $LogPath -Message "警告: $Description 失敗(結束碼 $LASTEXITCODE): $output"
            return $false
        }
        return $true
    } catch {
        Write-NetGuardLog -LogPath $LogPath -Message "警告: $Description 拋出例外: $($_.Exception.Message)"
        return $false
    }
}

function Ensure-FirewallServiceRunning {
    # 修正 #1:kid 若直接把 Windows Firewall 服務 (mpssvc) 停掉,
    # 所有 Get/New-NetFirewallRule 呼叫會「看似」正常執行但實際不生效或報錯不明顯。
    # 呼叫端應在動任何防火牆規則前先呼叫這個函式確認服務活著。
    param([string]$LogPath)

    $svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-NetGuardLog -LogPath $LogPath -Message "嚴重:找不到 Windows Firewall 服務 (mpssvc),無法繼續"
        return $false
    }

    if ($svc.Status -ne "Running") {
        Write-NetGuardLog -LogPath $LogPath -Message "偵測到 Windows Firewall 服務 (mpssvc) 未執行,狀態=$($svc.Status),嘗試啟動"
        try {
            Start-Service -Name mpssvc -ErrorAction Stop

            # 修正 #6:改成迴圈重試確認,而非固定等 2 秒就假設一定好了
            $started = $false
            for ($i = 0; $i -lt 5; $i++) {
                Start-Sleep -Seconds 1
                $svc.Refresh()
                if ($svc.Status -eq "Running") { $started = $true; break }
            }

            if ($started) {
                Write-NetGuardLog -LogPath $LogPath -Message "已成功重新啟動 Windows Firewall 服務"
                return $true
            } else {
                Write-NetGuardLog -LogPath $LogPath -Message "嘗試啟動 Windows Firewall 服務後,等待 5 秒狀態仍為 $($svc.Status)"
                return $false
            }
        } catch {
            # 修正 #5:給出具體下一步指令,而不是只說「可能被 Disabled」
            Write-NetGuardLog -LogPath $LogPath -Message "啟動 Windows Firewall 服務失敗: $($_.Exception.Message)。若服務啟動類型為 Disabled,請手動執行: Set-Service mpssvc -StartupType Manual,再重新執行本腳本"
            return $false
        }
    }
    return $true
}

function Ensure-FirewallProfileEnabled {
    # 修正 P1:kid 不需要停掉 mpssvc 服務,單純執行
    # Set-NetFirewallProfile -All -Enabled False 就能讓所有規則失效,
    # 但服務本身仍在 Running,Ensure-FirewallServiceRunning 會誤判一切正常。
    # 這裡專門檢查 Domain/Private/Public 三個 profile 是否都是 Enabled。
    param([string]$LogPath)

    try {
        $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
        $disabled = $profiles | Where-Object { $_.Enabled -eq $false -or $_.Enabled.ToString() -eq "False" }

        if ($disabled) {
            $names = ($disabled | ForEach-Object { $_.Name }) -join ", "
            Write-NetGuardLog -LogPath $LogPath -Message "偵測到防火牆設定檔已被停用: $names,嘗試重新啟用"
            Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop

            $recheck = Get-NetFirewallProfile -All -ErrorAction Stop
            $stillDisabled = $recheck | Where-Object { $_.Enabled -eq $false -or $_.Enabled.ToString() -eq "False" }
            if ($stillDisabled) {
                Write-NetGuardLog -LogPath $LogPath -Message "重新啟用防火牆設定檔後仍有異常: $(($stillDisabled | ForEach-Object { $_.Name }) -join ', ')"
                return $false
            }
            Write-NetGuardLog -LogPath $LogPath -Message "已成功重新啟用所有防火牆設定檔"
        }
        return $true
    } catch {
        Write-NetGuardLog -LogPath $LogPath -Message "檢查/啟用防火牆設定檔失敗: $($_.Exception.Message)"
        return $false
    }
}

function Send-NetGuardWebhook {
    # 修正 P0:原本用 ConvertFrom-Json -AsHashtable 解析 throttle 狀態,
    # 但 -AsHashtable 是 PowerShell 6.0+ 才有的參數,Windows 11 內建 PowerShell 5.1 沒有,
    # 會直接拋例外被 catch 吞掉、throttle 永遠不生效。
    # 改成方案 B:一個 EventKey 對應一個純文字時間戳檔案,完全不碰 JSON parsing,5.1/7.x 都相容。
    param(
        [Parameter(Mandatory=$true)][string]$ConfigPath,
        [Parameter(Mandatory=$true)][string]$EventKey,
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    if (-not (Test-Path $ConfigPath)) { return }

    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        if (-not $config.WebhookUrl) { return }

        $throttleDir = Split-Path -Path $ConfigPath -Parent
        if (-not (Test-Path $throttleDir)) { New-Item -Path $throttleDir -ItemType Directory -Force | Out-Null }

        $throttleFile = Join-Path $throttleDir "webhook_throttle_$EventKey.txt"
        $occurrenceFile = Join-Path $throttleDir "occurrence_$EventKey.txt"
        $now = Get-Date

        # 修正 P3:occurrence 計數移到 throttle 檢查「之後」才累加。
        # 之前的寫法是不管有沒有被抑制都先 +1,會導致計數膨脹到跟實際通知次數對不上
        # (例如 5 分鐘窗口內同一問題被偵測 12 次但只送出 1 次通知,計數卻累加到 12)。
        # 現在的邏輯:計數只反映「真的送出通知」的次數。
        if (Test-Path $throttleFile) {
            $rawTimestamp = (Get-Content $throttleFile -Raw).Trim()
            $lastSent = $null
            try { $lastSent = [datetime]$rawTimestamp } catch {
                Write-NetGuardLog -LogPath $LogPath -Message "警告: webhook_throttle_$EventKey.txt 時間戳格式無法解析('$rawTimestamp'),視為未曾送過"
            }
            if ($lastSent -and (($now - $lastSent).TotalMinutes -lt $script:NetGuardThrottleWindowMinutes)) {
                Write-NetGuardLog -LogPath $LogPath -Message "Webhook 已被 throttle 抑制(事件:$EventKey,距上次通知 $([math]::Round(($now-$lastSent).TotalMinutes,1)) 分鐘)"
                return
            }
        }

        $occurrence = 1
        if (Test-Path $occurrenceFile) {
            try {
                $occurrence = [int](Get-Content $occurrenceFile -Raw).Trim() + 1
            } catch {
                Write-NetGuardLog -LogPath $LogPath -Message "警告: occurrence_$EventKey.txt 內容無法解析為數字,已重置為 1"
                $occurrence = 1
            }
        }
        $occurrence | Out-File -FilePath $occurrenceFile -Encoding utf8 -Force

        $fullMessage = "$Message(第 $occurrence 次通知)"
        $payload = @{ content = "[NetGuard] $fullMessage ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))" } | ConvertTo-Json
        Invoke-RestMethod -Uri $config.WebhookUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 5 | Out-Null

        $now.ToString("o") | Out-File -FilePath $throttleFile -Encoding utf8 -Force
    } catch {
        Write-NetGuardLog -LogPath $LogPath -Message "Webhook 通知失敗: $($_.Exception.Message)"
    }
}

function Reset-NetGuardOccurrence {
    # 修正 P2 #4 的另一半:問題解除後呼叫這個函式清掉計數,
    # 讓下次問題再發生時是從「第 1 次」重新算,而不是無限累加下去
    param(
        [Parameter(Mandatory=$true)][string]$ConfigPath,
        [Parameter(Mandatory=$true)][string]$EventKey
    )
    $throttleDir = Split-Path -Path $ConfigPath -Parent
    $occurrenceFile = Join-Path $throttleDir "occurrence_$EventKey.txt"
    if (Test-Path $occurrenceFile) {
        Remove-Item -Path $occurrenceFile -Force -ErrorAction SilentlyContinue
    }
}
