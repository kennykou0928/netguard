# tests/NetGuard-Common.Tests.ps1
# Pester 5 測試,只測 NetGuard-Common.ps1 裡的「純函式」(不動防火牆、不動系統)。
# 其他 8 個腳本靠 PSScriptAnalyzer 在 GitHub Actions 跑 syntax + best practice 檢查。

BeforeAll {
    $script:NetGuardCommon = Join-Path $PSScriptRoot "..\NetGuard-Common.ps1"
    . $script:NetGuardCommon
}

Describe "Write-NetGuardLog" {

    BeforeEach {
        $script:LogPath = Join-Path ([System.IO.Path]::GetTempPath()) "netguard_test_$(Get-Random).log"
    }

    AfterEach {
        foreach ($variant in @($script:LogPath, "$script:LogPath.1", "$script:LogPath.2")) {
            Remove-Item $variant -Force -ErrorAction SilentlyContinue
        }
    }

    It "creates log file with timestamp prefix and message" {
        Write-NetGuardLog -LogPath $script:LogPath -Message "hello world"
        Test-Path $script:LogPath | Should -BeTrue
        $content = Get-Content $script:LogPath -Raw
        $content | Should -Match "hello world"
        # 確認時間戳格式為 YYYY-MM-DD HH:MM:SS 在訊息前面
        $content | Should -Match "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} hello world"
    }

    It "appends to existing log file (不覆蓋)" {
        Write-NetGuardLog -LogPath $script:LogPath -Message "first"
        Write-NetGuardLog -LogPath $script:LogPath -Message "second"
        $content = Get-Content $script:LogPath -Raw
        $content | Should -Match "first"
        $content | Should -Match "second"
        # 兩行訊息都被保留
        $lines = ($content -split "`n" | Where-Object { $_.Trim() })
        $lines.Count | Should -Be 2
    }

    It "會自動建立不存在的 log 目錄" {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "netguard_test_dir_$(Get-Random)"
        $logInNewDir = Join-Path $tempDir "nested\log.log"
        Write-NetGuardLog -LogPath $logInNewDir -Message "深層測試"
        Test-Path $logInNewDir | Should -BeTrue
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "當 log 檔案超過 1MB 時自動 rotate (.1 不存在時直接輪替)" {
        # 預先填入超大內容,觸發 rotate 邏輯
        $bigContent = "x" * 1500000
        $bigContent | Out-File -FilePath $script:LogPath -Encoding utf8 -Force
        Write-NetGuardLog -LogPath $script:LogPath -Message "rotate trigger"
        Test-Path "$script:LogPath.1" | Should -BeTrue
        $content = Get-Content $script:LogPath -Raw
        $content | Should -Match "rotate trigger"
        # 原檔內容應該幾乎都是 x,新檔則只是一行訊息
        $newSize = (Get-Item $script:LogPath).Length
        $newSize | Should -BeLessThan 100000
    }

    It "rotate 時正確保留兩份歷史 (.1 較新 -> .2 較舊)" {
        # .1 預先存在,確認輪替時 .1 會先被搬去 .2
        "$script:LogPath.1" | Out-File -FilePath "$script:LogPath.1" -Encoding utf8 -Force
        $bigContent = "y" * 1500000
        $bigContent | Out-File -FilePath $script:LogPath -Encoding utf8 -Force
        Write-NetGuardLog -LogPath $script:LogPath -Message "second rotation"
        Test-Path "$script:LogPath.2" | Should -BeTrue
        Test-Path "$script:LogPath.1" | Should -BeTrue
        $content1 = Get-Content "$script:LogPath.1" -Raw
        $content1 | Should -Match "^y+$"
        Remove-Item "$script:LogPath.2", "$script:LogPath.1" -Force -ErrorAction SilentlyContinue
    }
}

Describe "Reset-NetGuardOccurrence" {

    It "在 occurrence 檔案不存在時不拋例外" {
        $tempConfig = Join-Path ([System.IO.Path]::GetTempPath()) "test_config_$(Get-Random).json"
        @{ WebhookUrl = "test" } | ConvertTo-Json | Out-File $tempConfig
        $randomKey = "non_existent_$(Get-Random)"
        { Reset-NetGuardOccurrence -ConfigPath $tempConfig -EventKey $randomKey } | Should -Not -Throw
        Remove-Item $tempConfig -Force
    }

    It "會刪除對應 EventKey 的 occurrence 檔案" {
        $tempDir = [System.IO.Path]::GetTempPath()
        $tempConfig = Join-Path $tempDir "test_config_$(Get-Random).json"
        @{ WebhookUrl = "test" } | ConvertTo-Json | Out-File $tempConfig
        $eventKey = "test_event_$(Get-Random)"
        $occurrencePath = Join-Path $tempDir "occurrence_$eventKey.txt"
        "5" | Out-File $occurrencePath -Encoding utf8 -Force

        Test-Path $occurrencePath | Should -BeTrue
        Reset-NetGuardOccurrence -ConfigPath $tempConfig -EventKey $eventKey
        Test-Path $occurrencePath | Should -BeFalse

        Remove-Item $tempConfig -Force
    }

    It "刪除指定 EventKey 時不影響其他 EventKey 的 occurrence 檔案" {
        $tempDir = [System.IO.Path]::GetTempPath()
        $tempConfig = Join-Path $tempDir "test_config_$(Get-Random).json"
        @{ WebhookUrl = "test" } | ConvertTo-Json | Out-File $tempConfig
        $keyA = "keyA_$(Get-Random)"
        $keyB = "keyB_$(Get-Random)"
        $pathA = Join-Path $tempDir "occurrence_$keyA.txt"
        $pathB = Join-Path $tempDir "occurrence_$keyB.txt"
        "1" | Out-File $pathA -Encoding utf8 -Force
        "2" | Out-File $pathB -Encoding utf8 -Force

        Reset-NetGuardOccurrence -ConfigPath $tempConfig -EventKey $keyA
        Test-Path $pathA | Should -BeFalse
        Test-Path $pathB | Should -BeTrue

        Remove-Item $tempConfig, $pathB -Force
    }
}

Describe "Invoke-Icacls" {

    It "在 icacls 故意失敗時回傳 false 而不是拋例外" {
        # 故意給不存在的路徑 + 不合法 grant 語法,icacls 會回傳非 0 退出碼
        $logPath = Join-Path ([System.IO.Path]::GetTempPath()) "icacls_test_$(Get-Random).log"
        $result = Invoke-Icacls -Arguments @("C:\不存在的路徑\_xyz_$(Get-Random)", "/grant", "NotARealUser:F") -LogPath $logPath -Description "故意失敗"
        $result | Should -BeFalse
        Remove-Item $logPath -Force -ErrorAction SilentlyContinue
    }
}
