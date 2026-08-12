# Warn-Bedtime.ps1
# 由 SysNetSvc-4476 排程任務於每日 20:50 觸發。
# 任務本身用 LogonType Interactive + 綁定兒子帳號,所以只在該帳號登入前台時才會執行,
# 沒人登入就不會跳訊息(同 Lock-Screen 21:00 的設計)。

. "$PSScriptRoot\NetGuard-Common.ps1"

$logPath = "C:\ProgramData\NetGuard\warn.log"

try {
    Write-NetGuardLog -LogPath $logPath -Message "睡前提醒已觸發(帳號於前台登入中)"
    # msg * 會廣播給目前互動中的 session;因為任務本身設定成只在該帳號互動登入時才會執行,
    # 實際上就是跳給他看。如果他按「確定」關掉,Windows 架構上無法強制停留,
    # 但 21:00 Lock-Screen 一到就會強制鎖畫面,在那之前讓他自己決定要不要趕一段進度。
    msg * "九點斷網 做好睡前該做的 關機 睡覺"
} catch {
    Write-NetGuardLog -LogPath $logPath -Message "睡前提醒執行失敗: $($_.Exception.Message)"
}
