# NetGuard 🐾

> Windows 家用版的情境式網路控管:每天 21:00 自動封鎖、07:00 自動恢復,中間用 Watchdog + Audit 雙保險防止小朋友破解。
>
> 📦 **GitHub repo**: <https://github.com/kennykou0928/netguard>

## 故事

家用 Windows 10/11 沒有「家長監護」內建可擋網路,小孩一旦找到 admin 密碼或裝了什麼第三方工具就能破解。本系統用「**排程封鎖 + 自我修復式防禦**」在不靠家長每天手動操作的前提下,提供 7×24 的網路宵禁。

## 核心特性

- 🕐 **時間式封鎖** — 每天 21:00 自動封、07:00 自動開,排程任務驅動
- 🌙 **20:50 睡前提醒** — 跳出「九點斷網 做好睡前該做的 關機 睡覺」系統訊息,給兒子 10 分鐘緩衝
- 🔒 **深度保險** — 21:00 自動鎖畫面、Activities 期間 kid 觸不到桌面
- 🐕 **Watchdog 主動修復** — 每 1 分鐘檢查,kid 改 Action / 刪規則會自動重建
- 🦴 **Audit 唯讀稽核** — 每 5 分鐘唯讀檢查,有異常才通知,不修改任何東西
- 📢 **Discord 通知** — 異常時透過 webhook 推播到 Discord,可知道發生了什麼
- 🔐 **NTFS 鎖定** — 安裝目錄全部鎖成「只有 SYSTEM/Administrators 可寫」,標準使用者只讀
- 🐶 **完整 rollback** — Setup 失敗會自動撤銷已建立的任務,不留半套
- 🦊 **throttle 防洗版** — 同一 EventKey 5 分鐘內只送一次 discord 通知,避免重複刷頻
- 🐾 **每日心跳** — Audit 每天寫一次 `audit_heartbeat.txt`,讓你知道「稽核還活著」

## 威脅模型

| 攻擊 | 防禦 |
|---|---|
| 小朋友用 Windows 設定關網路 | Watchdog 每分鐘重建規則 |
| 改 Action 從 Block 改成 Allow | Watchdog 會偵測並重建 |
| 刪除 NetFirewallRule | Watchdog 會重建 |
| `Set-NetFirewallProfile -All -Enabled False` | Watchdog 偵測 Profile 停用並自動 Re-enable |
| `Stop-Service mpssvc` | Watchdog 自動啟動 mpssvc |
| 刪除所有排程任務 | Audit 每 5 分鐘偵測並通知 |
| 讀設定檔偷 Webhook URL | config.json 鎖成只有 SYSTEM/Administrators 可讀 |
| 寫檔改 Watchdog 腳本 | 安裝目錄鎖成只有 SYSTEM/Administrators 可寫 |
| 跨帳號 (admin 給自己開) | 建議用 `Set-AccountType.ps1 -Mode standard` 強制降級 |

**不防禦的場景**:
- 安全模式開機(Windows 架構限制,排程任務在安全模式不執行)
- 小朋友知道你的 admin 密碼直接登入 admin
- 小朋友用 USB 開機進入另一個 OS
- 物理接觸(拔硬碟、進 BIOS)

## 系統需求

- Windows 10 / 11 **家用版**皆可(已驗證 22H2)
- PowerShell 5.1 內建(不需要額外安裝)
- 需要一個「系統管理員」帳號(執行 Setup)
- Discord webhook(選擇性,但建議設定,才能收到通知)

## 安裝

### 1. 下載/clone 此 repo

```bash
# SSH (推薦,適合已設 GitHub SSH key 的使用者)
git clone git@github.com:kennykou0928/netguard.git netguard

# HTTPS (需要 GitHub Personal Access Token,適合沒設 SSH key 的使用者)
git clone https://github.com/kennykou0928/netguard.git netguard

cd netguard
```

### 2. ⚠️ 必讀:備援管理員帳號(只有 1 個帳號的機器必跑)

降級 kid 帳號為標準使用者前,**本機必須至少還有 1 個啟用中的系統管理員帳號**。Windows 不允許移除最後一個 admin,且 `Set-AccountType.ps1` 會自動擋下這種嘗試。

如果這台機器**目前只有 1 個帳號**(就是 kid 帳號),請先跑:

```powershell
# 以「系統管理員」身分(內建 Administrator 啟用,或目前登入的 admin)
.\New-GuardianAdmin.ps1 -AccountName "SvcMaintUser"
# 互動式輸入密碼(12 碼以上,不會顯示在螢幕)
```

這會建立備援 admin、加入 Administrators 群組、從歡迎畫面隱藏。冪等可重跑。

**重要誠實聲明**:`HideUser` 只是「不在歡迎畫面顯示」,**Standard User 用 `Get-LocalUser` 還是看得到帳號名稱**。真正的安全邊界是**(a) 密碼強度 + (b) 你不告訴 kid 密碼**,不是帳號名稱保密。請用密碼管理員產生 14 碼以上亂碼密碼,帳號名稱藏得再好也沒用,密碼夠強 + 嚴守不外洩才是真正的防線。

跑完後可以用 `.\Verify-AdminAccess.ps1 -KidUsername "kid_account"` 驗證備援帳號確實在 Administrators 群組。

### 3. 確認 kid 帳號是「標準使用者」(很重要)

```powershell
# 檢查狀態
.\Set-AccountType.ps1 -Mode status -Username "kid_account"

# 如果顯示 Administrator,降級為標準使用者(腳本會自動確認還有其他 admin 才允許)
.\Set-AccountType.ps1 -Mode standard -Username "kid_account"
```

降級後**必須登出再登入**才會生效。

### 4. 取得 Discord webhook URL(選用,但建議)

1. Discord 頻道 → 設定 → 整合 → Webhook → 新 Webhook
2. 複製 Webhook URL
3. 測試貼到瀏覽器確認格式正確

### 5. 執行 Setup

```powershell
# 以「系統管理員」身分開啟 PowerShell
cd <repo 路徑>
.\Setup-NetGuard.ps1 -KidUsername "kid_account" -WebhookUrl "https://discord.com/api/webhooks/123456789/abcdef..."
```

參數:
- `-KidUsername <name>` **(必填)** — 要控管的帳號
- `-WebhookUrl <url>` **(選填,但建議)** — Discord webhook

執行成功的話會看到:

```
收到的 WebhookUrl(前 50 字元): https://discord.com/api/webhooks/123456789012...
已對 C:\ProgramData\NetGuard 及其內容套用 NTFS 鎖定
安裝完成,已建立並驗證 6 個排程任務:
  SysNetSvc-4476 -> 20:50 跳出睡前提醒(僅在 kid_account 於前台登入時觸發)
  SysNetSvc-4471 -> 21:00 封鎖網路
  SysNetSvc-4472 -> 07:00 恢復網路
  SysNetSvc-4473 -> 每 1 分鐘檢查,防止手動關閉/竄改規則(異常時主動修復)
  SysNetSvc-4474 -> 21:00 鎖定畫面(僅在 kid_account 於前台登入時觸發)
  SysNetSvc-4475 -> 每 5 分鐘唯讀稽核,異常只通知不修復
```

### 6. 測試

立刻觸發 watchdog 確認運作(不影響封鎖時段):

```powershell
Get-ScheduledTask -TaskName SysNetSvc-4473 | Start-ScheduledTask
# 檢查 C:\ProgramData\NetGuard\watchdog.log
```

觀察 Discord 是否收到任意一條通知(如果有的話代表 webhook 通了)。

## 日常使用

### 查看帳號權限狀態(稽核模式)

```powershell
.\Set-AccountType.ps1 -Mode audit
```

會一次列出:

- 🐾 目前 Administrators 群組成員
- 🐾 所有本機帳號 + 啟用狀態 + 最後登入時間(用 `Win32_UserProfile.LastUseTime`,家用版有時讀不到,會標 `N/A` 並彙總警告)
- 🐾 用來確認「kid 帳號已降級 + 還有可用 admin」這個安全前提沒被破壞

適合定期跑一次(例如每次重開機後、或懷疑被改過時),看一下系統狀態是否符合預期。**只讀**,不會修改任何東西。

### 調整封鎖時間

編輯 `Block-Internet.ps1`、`Unblock-Internet.ps1`、`NetGuard-Watchdog.ps1`、`NetGuard-Audit.ps1`、`Lock-Screen.ps1` 內的 `$blockStartHour` 與 `$blockEndHour`(預設 21 與 7),然後重新跑 `Setup-NetGuard.ps1`,它會自動覆蓋任務的觸發時間。

(Setup 不會自動同步腳本內的常數時段,因為時間政策是寫在腳本裡的。如果你只在 Setup 改了時間但忘了同步腳本,Watchdog 與 Setup 排程會對不上。)

### 看 log

所有 log 在 `C:\ProgramData\NetGuard\`:

| 檔案 | 紀錄內容 |
|---|---|
| `block.log` | 21:00 封鎖網路時的詳細記錄 |
| `unblock.log` | 07:00 恢復網路時的詳細記錄 |
| `watchdog.log` | 每分鐘偵測結果(tamper 修復、服務啟動...) |
| `lock.log` | 鎖屏任務觸發記錄 |
| `warn.log` | 20:50 睡前提醒觸發記錄 |
| `audit.log` | 每 5 分鐘稽核結果 + 每日心跳 |
| `install.log` | 安裝/移除時的 NTFS 鎖定紀錄 |
| `audit_heartbeat.txt` | 今日最後一次成功稽核的日期(YYYY-MM-DD) |

每個 log 1MB 自動 rotate,保留 `.1`(較新)、`.2`(較舊)兩份歷史。

### 手動觸發任務

```powershell
# 立刻測試封鎖
Get-ScheduledTask -TaskName SysNetSvc-4471 | Start-ScheduledTask

# 立刻測試恢復
Get-ScheduledTask -TaskName SysNetSvc-4472 | Start-ScheduledTask

# 立刻看 watchdog 跑一次的結果
Get-ScheduledTask -TaskName SysNetSvc-4473 | Start-ScheduledTask

# 立刻看 audit 跑一次的結果
Get-ScheduledTask -TaskName SysNetSvc-4475 | Start-ScheduledTask

# 立刻測試睡前提醒(僅在 kid 帳號登入時觸發)
Get-ScheduledTask -TaskName SysNetSvc-4476 | Start-ScheduledTask
```

### 還原 kid 帳號為系統管理員(若需要)

```powershell
.\Set-AccountType.ps1 -Mode admin -Username "kid_account"
```

(這只是暫時還原。**移除 NetGuard 之後也要記得還原**,卸載腳本不會自動做這件事。)

## 移除

```powershell
# 以「系統管理員」身分
.\Uninstall-NetGuard.ps1
```

它會依序停用並刪除 6 個排程任務、移除 2 條防火牆規則、刪除整個 `C:\ProgramData\NetGuard`。**不會動** kid 帳號的權限狀態。

## 檔案結構

```
netguard/
├── README.md                    # 本檔案
├── CHANGELOG.md                 # 修補歷史
├── Setup-NetGuard.ps1           # 安裝(主入口)
├── Uninstall-NetGuard.ps1       # 移除
├── Set-AccountType.ps1          # 帳號權限管理(降級/升級/查詢)
├── New-GuardianAdmin.ps1        # 建立備援管理員帳號(只有 1 個帳號的環境必跑)
├── Verify-AdminAccess.ps1       # 驗證降權後 admin 路徑仍可用(結構化 PASS/FAIL)
├── Block-Internet.ps1           # 21:00 封鎖網路
├── Unblock-Internet.ps1         # 07:00 恢復網路
├── Lock-Screen.ps1              # 21:00 鎖定畫面
├── NetGuard-Watchdog.ps1        # 每 1 分鐘主動防禦
├── NetGuard-Audit.ps1           # 每 5 分鐘唯讀稽核
├── Warn-Bedtime.ps1             # 20:50 睡前提醒
└── NetGuard-Common.ps1          # 共用函式庫
```

## 各腳本職責

| 腳本 | 角色 | 觸發時間 | 帳號 |
|---|---|---|---|
| `Setup-NetGuard.ps1` | 安裝入口 | 手動 | 系統管理員 |
| `Uninstall-NetGuard.ps1` | 移除 | 手動 | 系統管理員 |
| `Set-AccountType.ps1` | 帳號權限管理 | 手動 | 系統管理員 |
| `New-GuardianAdmin.ps1` | 建立備援管理員帳號 | 手動 | 系統管理員 |
| `Verify-AdminAccess.ps1` | 驗證降權後 admin 路徑 | 手動 | 任何(唯讀) |
| `Block-Internet.ps1` | 執行封鎖 | 每日 21:00 | SYSTEM |
| `Unblock-Internet.ps1` | 執行恢復 | 每日 07:00 | SYSTEM |
| `Lock-Screen.ps1` | 鎖畫面 | 每日 21:00 | kid (Interactive) |
| `NetGuard-Watchdog.ps1` | 1 分鐘偵測 + 修復 | 持續 | SYSTEM |
| `NetGuard-Audit.ps1` | 5 分鐘唯讀稽核 | 持續 | SYSTEM |
| `Warn-Bedtime.ps1` | 20:50 睡前提醒 | 每日 20:50 | kid (Interactive) |
| `NetGuard-Common.ps1` | 共用函式庫 | (被 dot-source) | — |

## 設計原則

1. **失敗要看得見** — 每個外部指令(icacls、Set-Service、Register-ScheduledTask)都用 try/catch + `-ErrorAction Stop` 包,失敗會印出原因,不會默默出錯。
2. **不要被監控者監控** — kid 帳號在 Authenticated Users 群組只讀,改不了任何腳本。
3. **自我修復優先,通知次之** — Watchdog 嘗試自己修,修不好才送 webhook。Audit「絕不修改」,只通知。
4. **idempotent** — Setup 跑第二次會自動 Skip 已存在的任務,不會壞掉現有的部署。
5. **rollback 安全** — Setup 中途失敗會自動撤銷,只刪「這次新增」的任務,不會刪到先前的部署。
6. **throttle 防洗版** — 同一類通知 5 分鐘內只送一次,避免重複刷頻。
7. **PowerShell 5.1/7.x 相容** — 完全不用 PowerShell 6+ 才有的參數(`-AsHashtable` 等),確保 Windows 內建 5.1 跑得起來。

## 部署前測試清單

至少要跑過這 7 項:

1. ✅ **完整 block/unblock 循環** — 手動觸發 4471 / 4472,觀察 log
2. ✅ **Webhook 通知** — `Stop-Service mpssvc -Force`,等 1 分鐘,看 Discord 有沒有訊息
3. ✅ **防火牆 profile 攻擊** — `Set-NetFirewallProfile -All -Enabled False`,watchdog 自動 re-enable
4. ✅ **規則刪除攻擊** — `(封鎖時段內) Remove-NetFirewallRule -DisplayName "NetGuard_Block_Outbound"`,watchdog 重建
5. ✅ **任務刪除攻擊** — `Unregister-ScheduledTask -TaskName SysNetSvc-4473`,audit 5 分鐘內通知
6. ✅ **停掉 mpssvc startup type** — `Set-Service mpssvc -StartupType Disabled`,watchdog 報錯並給提示
7. ✅ **Kid 帳號 NTFS 鎖定** — `Get-Content C:\ProgramData\NetGuard\config.json` 應 Access Denied

## 自我檢查限制

最重要的一個限制:**如果 SysNetSvc-4475 稽核任務本身也被刪掉,沒有任何機制會通知你**。建議偶爾手動查:

```powershell
Get-ScheduledTask -TaskName SysNetSvc-4475
```

或檢查今日心跳:

```powershell
Get-Content C:\ProgramData\NetGuard\audit_heartbeat.txt
```

## 授權

MIT

---

> 🐶 "真正的守護不是衝動地撲上去咬壞人,而是先嗅清楚,再精準出手。" — Puppy
