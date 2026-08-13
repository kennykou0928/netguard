# Warn-Bedtime.ps1
# 由 Interactive 排程任務(綁定兒子帳號)於 20:50 觸發,跳出系統訊息視窗

. "$PSScriptRoot\NetGuard-Common.ps1"

$logPath = "C:\ProgramData\NetGuard\warn.log"

try {
    Write-NetGuardLog -LogPath $logPath -Message "睡前提醒已觸發(帳號於前台登入中)"
    # msg * 會廣播給目前互動中的 session;因為此任務本身就設定成只在該帳號互動登入時才會執行,
    # 實際上就是跳給他看
    msg * "九點斷網 做好睡前該做的 關機 睡覺"
} catch {
    Write-NetGuardLog -LogPath $logPath -Message "睡前提醒執行失敗: $($_.Exception.Message)"
}
