# Changelog

## [v6] — 2026-08-12

### 全部 P3 修補完成 🎉

這版正式收尾,從 v5 (P0/P1/P2 修完) 之後剩下的所有 P3 nice-to-have / minor bug 全部處理。

### 修正

- 🐛 **Minor Bug** — `Unblock-Internet.ps1` 寫到 `block.log`,改成 `unblock.log` 避免「已封鎖」與「已恢復」訊息混在同一個檔案
- 🐾 **P3 #1** — `NetGuard-Watchdog.ps1` 新增正常狀態時 `Reset-NetGuardOccurrence -EventKey "tamper_detected"`,避免長期運作下發生「(第 5460 次通知)」這種累計誤判
- 🐾 **P3 #2** — `NetGuard-Common.ps1` 新增 `Invoke-Icacls` 函式,所有 `icacls` 呼叫改走這個函式,失敗會印出結束碼與輸出,不再無條件 `Out-Null` 吞掉錯誤
- 🐾 **P3 #3** — `Set-AccountType.ps1` audit mode CIM 查詢失敗改成「收集後彙總印一次」,不再每個帳號各印一行洗畫面
- 🐾 **P3 #4** — `Send-NetGuardWebhook` occurrence 計數移到 throttle 檢查「之後」,計數現在精準反映「真的送出通知」的次數,訊息改用「(第 N 次通知)」更明確

### 已知未修

- 🐾 **P4** — `firewall_service_down` / `firewall_profile_disabled` 這兩個 EventKey 在 watchdog 成功修復後未呼叫 `Reset-NetGuardOccurrence`,長期下來計數仍會累加;但 Audit 會用 `audit_anomaly` 抓到這兩個狀況,而 `audit_anomaly` 有正常 reset,實際影響輕微

### 評價

- ✅ 全部 P0/P1/P2/P3 修完
- ✅ 檔案命名已修正
- ✅ 部署前 7 項測試全可執行
- 🎯 **production-ready**

---

## [v5] — 2026-08-12

### P0/P1/P2 全部修補

### 修正

- 🔴 **P0 Bug A** — `Send-NetGuardWebhook` 原本用 `ConvertFrom-Json -AsHashtable` 解析 throttle 狀態;`-AsHashtable` 在 PowerShell 6.0+ 才有,Windows 內建 5.1 沒有,會直接拋例外被 catch 吞掉、throttle 永遠不生效。**改成方案 B**:每個 EventKey 一個純文字時間戳檔案 + occurrence 計數檔,完全不碰 JSON parsing,5.1/7.x 都相容
- ⚠️ **P1 #1** — `Uninstall-NetGuard.ps1` 的 `$stopOrder` 修正為 `("SysNetSvc-4475", "SysNetSvc-4473", "SysNetSvc-4471", "SysNetSvc-4472", "SysNetSvc-4474")`,audit 必須最先停,避免「任務被刪但仍有空檔觸發」誤判
- ⚠️ **P1 #2** — `Setup-NetGuard.ps1` 對 `-WebhookUrl` 加 `Trim()` + 印出前 50 字元預覽,避免從 Discord 複製貼上時夾帶不可見字元
- ⚠️ **P1 #3** — `Setup-NetGuard.ps1` 對 `-WebhookUrl` 加 regex 驗證 `^https://discord(app)?\.com/api/webhooks/\d+/[\w-]+$`,防止貼錯字串
- 🐾 **P2 #4** — `NetGuard-Audit.ps1` 異常解除後呼叫新的 `Reset-NetGuardOccurrence` 函式清掉計數,下次異常從「第 1 次」重新算
- 🐾 **P2 #5** — `NetGuard-Audit.ps1` 完全正常時每天寫一次 `audit_heartbeat.txt` 心跳,讓你知道「稽核真的有在跑」,而不是「任務已經死了」
- 🐾 **P2 #6** — `Setup-NetGuard.ps1` 安裝完成時印出自我檢查限制提醒(`SysNetSvc-4475 本身被刪沒人會通知`)

### 新增

- 🦴 `NetGuard-Common.ps1` 新增 `Reset-NetGuardOccurrence` 函式
- 🦴 `NetGuard-Audit.ps1` 用 `audit_anomaly` 獨立 EventKey,跟 Watchdog 的 throttle 分開

### 評價

- 🔴 P0 解除,功能不再靜默失敗
- ✅ P1/P2 全部修完
- 🐾 仍有少數 P3 與 minor bug 留到 v6

---

## [v4] — 2026-08-11

### 重大功能新增:稽核任務

### 新增

- 🦴 `NetGuard-Audit.ps1` — 獨立的「唯讀稽核」任務,每 5 分鐘跑一次,跟 Watchdog 用不同 EventKey 避免 throttle 衝突
- 🦴 `SysNetSvc-4475` 排程任務 — 部署 Audit 邏輯

### 為什麼需要 Audit? (Watchdog 不夠嗎?)

- Watchdog 是「主動修復」,只會在「有問題」時動作
- 沒問題時 Watchdog 完全沉默,你不知道它還在不在跑
- Audit 是「唯讀檢查」,就算沒問題也會定期確認,並對「任務被刪」這類所有任務都死了的狀況發出通知

### 評價

- ✅ Watchdog + Audit 雙保險架構完成
- ⚠️ 仍需大幅修補(P0/P1/P2 問題在 v5 解決)

---

## [v1~v3] — 2026-08-08 ~ 2026-08-10

### 初始版本演進

- v1:基本 block/unblock,用 `Set-NetFirewallRule` 即時切換
- v2:加入排程任務、`Set-Service mpssvc` 自動啟動
- v3:加入 Watchdog,加入 Discord webhook

### 已知問題 (在 v4+ 修補)

- ⚠️ P0:`-AsHashtable` PowerShell 5.1 不支援
- ⚠️ P1:Uninstall 順序錯誤,audit 會誤判
- ⚠️ P1:Webhook URL 沒 trim,容易貼錯
- ⚠️ P2:Audit 異常洗版,沒有 occurrence 計數
- ⚠️ P2:Audit 沒心跳,無法區分「正常」還是「已死」

---

## 修改建議專區

任何看到的「應該可以更好」但還沒實作的項目:

- 🐾 **P4** — Watchdog 應在 `Ensure-*` 函式成功時也 reset 對應 EventKey 的 occurrence
- 🐾 **P4** — `Set-AccountType.ps1 -Mode audit` 加 `LastPasswordChange` 資訊(可用 `net user <name>` 查)
- 🐾 **P4** — 加一個 `-Mode export` 把所有 audit 結果輸出成 CSV 方便長期追蹤
- 🐾 **P4** — README 圖文化(流程圖、log 截圖)
- 🐾 **P4** — `Setup-NetGuard.ps1` 加 `-DryRun` flag,不真的安裝,只印出會做什麼
- 🐾 **P4** — 把 `$blockStartHour` / `$blockEndHour` 抽到 `config.json` 統一管理,不要散落在 4 個腳本
