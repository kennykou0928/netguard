# Lock-Screen.ps1 (v6)

. "$PSScriptRoot\NetGuard-Common.ps1"

$logPath = "C:\ProgramData\NetGuard\lock.log"

try {
    Write-NetGuardLog -LogPath $logPath -Message "鎖屏任務已觸發(帳號於前台登入中)"
    rundll32.exe user32.dll,LockWorkStation
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Write-NetGuardLog -LogPath $logPath -Message "rundll32 回傳非 0 結束碼: $LASTEXITCODE"
    }
} catch {
    Write-NetGuardLog -LogPath $LogPath -Message "鎖屏執行失敗: $($_.Exception.Message)"
}
