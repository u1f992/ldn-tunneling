# LDN Tunneling — 作業ノート

## 環境情報
- **OS:** Ubuntu 24.04.4 LTS
- **Kernel:** 6.17.0-14-generic
- **Python:** 3.12.3 (uv管理)
- **ldn:** 0.0.16 (uv add済み)
- **mt76x2uドライバ:** カーネルモジュール利用可能、自動ロード確認済み
- **既存NIC:** wlp3s0 (内蔵Intel Wi-Fi, DOWN), wg0 (WireGuard, UP), eno1→br0 (有線LAN)

## A6210 ハードウェア情報
- **USB:** `0846:9053 NetGear, Inc. A6210`
- **インターフェース名:** `wlx94a67e5d7030`
- **phy:** phy1
- **MAC:** 94:a6:7e:5d:70:30
- **ファームウェア:** ROM patch 20141115, FW build 20150731
- **対応モード:** IBSS, managed, AP, AP/VLAN, **monitor**, mesh point, P2P-client, P2P-GO
- **active monitor対応:** YES (受信フレームにACKを返す)
- **ソフトウェア追加可能:** AP/VLAN, monitor (= monitorは常に追加可能)
- **同時インターフェース制約:** `{managed, AP, mesh, P2P} <= 2, total <= 2, 1チャネル`
  - → AP + monitor は可能（monitorはソフトウェアで常時追加可） ★kinnay/LDN要件OK
- **`frame`コマンド対応:** YES (nl80211経由のアクションフレーム送信)
- **2.4GHz:** ch1-14利用可能 (ch12-14はno IR)

## Phase 1: ローカル検証

### Step 1: A6210接続・ドライバ確認 ★完了
- [x] A6210をUSBに接続
- [x] `lsusb`でデバイス認識確認: 0846:9053 OK
- [x] `dmesg`でmt76x2uドライバ自動ロード確認: OK
- [x] `iw list`で対応モード確認: AP, monitor, managed 全対応
- [x] インターフェース名: wlx94a67e5d7030

### Step 2: LDNスキャンテスト ★完了
- [x] NetworkManagerからA6210を解放
- [x] rfkill unblock 2 (ソフトブロック解除が必要だった)
- [x] prod.keys を用意（master_key_00〜05, aes_kek/key_generation_source）
- [x] マリオカート8DXのローカル通信で部屋作成
- [x] スキャン成功: MAC 5C:52:1E:EA:EB:9E, GameID 0x0100152000022000, ch1, proto=1, ver=4
- 検出率: 5ラウンド中3回 (60%) — dwell=130ms
- LDN v4でもprotocol=1(master_key_00)で動作確認 → 現状のprod.keysで十分

### Step 3: LDNネットワーク参加テスト ★完了
- [x] MK8DXのパスワード判明: `MarioKart8Delux` + 17 null bytes (kinnay/NintendoClients wiki LDN-Passphrases)
- [x] LDNネットワークに参加成功: IP 169.254.89.2, MAC 94:A6:7E:5D:70:30
- ゲーム画面には表示されない（Pia層の通信を行っていないため、想定通り）
- トンネリングにはこれで十分 — データフレームの送受信が可能な状態
### Step 4: LDNネットワークホストテスト ★完了
- [x] MK8DXのネットワークパラメータをスキャンで取得（Phase 1）
- [x] 取得したパラメータでLinux PCがLDNネットワークをホスト（Phase 3）
- [x] Switchの「ローカル通信」画面からLinux PCのネットワークが見えることを確認
- kinnay/LDN v0.0.16 の wlan.py パッチ状況 **(ENETDOWN 根本原因判明後に再評価)**:
  - ~~鍵操作 (`NEW_KEY`/`SET_KEY`) 削除~~ → **不要。** ENETDOWN の原因は NM interference であり、
    NM 管理外設定 (`/etc/NetworkManager/conf.d/99-ldn-unmanaged.conf`) で解決。
    upstream コードの NEW_KEY/SET_KEY は正常に動作する
  - `REGISTER_FRAME` を `START_AP` の前に移動 → 要再検証 (NM 修正後も必要か)
  - **不要だったパッチ**:
    - `NL80211_ATTR_PRIVACY` フラグ追加 — AP モードでカーネルに影響しない
      (`ieee80211_start_ap()` は `params->privacy` を使用しない: linux@e5f0a69 `net/mac80211/cfg.c:1366-1622`)。
      ビーコンの Privacy ビットは `capability_information = 0x511` でハードコード済み
      (ldn@01259fe `ldn/wlan.py:1486`)。
      最初の ENETDOWN が PRIVACY 追加で「直った」のは偶然（タイミング差等）と考えられる。
    - `NEW_KEY`/`SET_KEY` の try/except — 削除すべきコードを温存していた
  - **参照コミット**:
    - linux: `e5f0a698b34ed76002dc5cff3804a61c80233a7a`
    - hostapd: `b624b164b9c17926405d7f04bfb194b6a286483c`
    - kinnay/LDN: `01259fe6a500b197fe1a9d84f89dc56216792081`
- **hostapd との比較** (hostapd@b624b16):
  - hostapd の順序: REGISTER_FRAME → START_AP → NEW_KEY (GTK)
    - フレーム登録: `src/drivers/driver_nl80211.c:6691` (`nl80211_mgmt_subscribe_ap`)
    - START_AP: `src/ap/hostapd.c:1770` (`hostapd_start_beacon`)
    - GTK インストール: `src/ap/hostapd.c:1773` (`wpa_init_keys`)
  - hostapd は GTK を START_AP 後にインストールするが、これはカーネル HW 暗号化を使うため
  - kinnay/LDN は HW 暗号化を使わない（monitor + Python CCMP）→ GTK インストール自体が不要
  - hostapd は START_AP に cipher suites / AKM / WPA version を含めるが、
    mac80211 はこれらを `control_port` 設定以外に使用しない
    (`ieee80211_start_ap()`: linux@e5f0a69 `net/mac80211/cfg.c:1514-1529`)
- **カーネルソース調査** (linux@e5f0a69):
  - `NL80211_ATTR_PRIVACY`: `net/wireless/nl80211.c:6338` で parse → mac80211 で未使用
  - `cfg80211_validate_key_settings()`: `net/wireless/util.c:313` — AP の暗号設定を参照しない
  - `ieee80211_start_ap()`: `net/mac80211/cfg.c:1366` — `SDATA_STATE_RUNNING` に触れない
  - `ieee80211_add_key()`: `net/mac80211/cfg.c:512-513` — `ieee80211_sdata_running()` チェック
  - `SDATA_STATE_RUNNING`: `net/mac80211/iface.c:1500` で設定、`iface.c:469` で解除
  - `drv_start_ap()`: `net/mac80211/driver-ops.h:1088` — mt76x2u 未実装 → ret=0
  - `mt76x2u_ops`: `drivers/net/wireless/mediatek/mt76/mt76x2/usb_main.c:90` — `start_ap` なし
  - `mgmt_stypes[AP].rx`: `net/mac80211/main.c:697-706` — 全必要フレームタイプを静的に許可
  - `mlme register check`: `net/wireless/mlme.c:685-688` — EINVAL の発生箇所
  - ~~REGISTER_FRAME EINVAL・NEW_KEY ENETDOWN とも、カーネルソースでは説明不能~~
    → **NEW_KEY ENETDOWN の根本原因は NetworkManager の race condition と判明** (後述)。
    REGISTER_FRAME EINVAL は要再検証

### Step 5: TAPインターフェース確認 ★完了
- [x] ホスト中に `ldn-tap` が EN10MB (Ethernet) インターフェースとして存在
- [x] tcpdump でパケットキャプチャ可能を確認
- Linux PC自身の mDNS (169.254.109.1:5353 → 224.0.0.251) と IPv6 RS が流れている
- Switch からのゲームパケットは確認できず（Pia層認証なしのため即切断）
- TAPデータパスは正常動作 — トンネリングの基盤として十分

## Phase 2: リモート接続 (L2 トンネル)

### アーキテクチャ
```
[Switch A] --LDN--> [PC A: ldn-tap] <-> [br-ldn] <-> [gretap1]
                                                        |
                                                    WireGuard
                                                        |
[Switch B] --LDN--> [PC B: ldn-tap] <-> [br-ldn] <-> [gretap1]
```
- 両拠点で `tunnel_node.py` を実行
- GRETAP over WireGuard で L2 トンネル構築
- Linux ブリッジ (`br-ldn`) で `ldn-tap` と `gretap1` を接続
- Switch 同士が LDN レイヤで直接通信可能になる想定

### Step 1: tunnel_node.py 準備 ★完了
- [x] `tunnel_node.py` 作成済み
- 機能:
  1. GRETAP トンネル + Linux ブリッジ (`br-ldn`) を作成
  2. MK8DX パラメータをスキャンで取得
  3. 取得パラメータで LDN ネットワークをホスト
  4. `ldn-tap` を `br-ldn` に接続
  5. 終了時にトンネル・ブリッジをクリーンアップ
- 使い方: `sudo .venv/bin/python tunnel_node.py prod.keys --local <wg_ip> --remote <wg_ip>`
- 前提: 両拠点間に WireGuard トンネルが構築済みであること

### Step 2: 単拠点動作確認 ★未着手
- [ ] tunnel_node.py を片側だけ起動し、GRETAP + ブリッジ作成まで動作確認
- [ ] ldn-tap がブリッジに正しく接続されることを確認
- [ ] Switch から LDN ネットワークが見えることを確認

### Step 3: 両拠点接続テスト ★未着手
- [ ] 両拠点で tunnel_node.py を起動
- [ ] 各 Switch がローカル通信で相手拠点のネットワークに参加できることを確認
- [ ] ゲーム内で対戦が成立することを確認

---

## ログ

### 2026-02-20: 初期セットアップ
- uv init + uv add ldn 完了

### 2026-02-20: A6210接続・ドライバ確認
- A6210接続 → mt76x2u自動ロード、インターフェース wlx94a67e5d7030 生成
- iw list結果: AP + monitor同時利用可能を確認 → kinnay/LDNの要件を満たす
- active monitor対応、frameコマンド対応 → アクションフレーム送受信の条件も良好
- 2.4GHz ch1-11がフルパワー利用可、ch12-14はno IR（LDNはch1-7を使うので問題なし）
- **判定: ハードウェア的にはGo**。次はスキャンテストへ。
- ★ レポートに記載漏れ: kinnay/LDNライブラリは `prod.keys`（Switch暗号鍵）が必須
  - LDNアドバタイズメントフレームの復号に使用
  - 入手にはCFW対応Switch or hactoolでのファームウェア解析が必要
  - プレイ用2台がOFWであることとは矛盾しないが、鍵入手ルートの確保が前提条件
  - 鍵はどの本体から取り出しても同一（ファームウェア共通鍵）
  - ライブラリ内部での使用箇所: アドバタイズ復号、認証ハンドシェイク、データフレームCCMP暗号化/復号
  - 「暗号化されたまま素通し」は不可 — ライブラリはLDNプロトコルに能動参加する設計
  - フロー: Switch→暗号化フレーム→ライブラリ復号→TAP(平文)→トンネル→TAP→ライブラリ暗号化→Switch
  - **配布性の課題:** prod.keys入手にCFW対応Switchが必要 → 万人向けソリューションにはならない
    - どの方式でもOFW Switchだけで完結する手段は現存しない
  - **アップストリーム確認後の整理 (version vs protocol):**
    - `version` = LDNプロトコルバージョン (2,3,4) — v4がデフォルト、対応済み
    - `protocol` = 暗号化方式の世代 — 1=AES-CTR(master_key_00), 3=AES-GCM(master_key_12)
    - protocol=1 は初代Switch系、protocol=3 はSwitch 2系（AES-GCM）
    - スキャン時は protocols=[1,3] で両方試行するので両世代を検出可能
    - Switch 2とのLDN通信には master_key_12 も必要になる可能性あり
    - master_key_XXはハードウェア秘密鍵+FWデータから導出（全コンソール共通、コンソール固有でない）
    - **確認済み (switchbrew):** master_key_12はFW 19.0.0で導入 — 初代SwitchでもFW 19.0.0+なら存在
    - 手元のprod.keysはmaster_key_05まで（FW 10.x前後で抽出） → master_key_12なし
    - 新しいFWのSwitchから再抽出すればmaster_key_12も得られる
    - 当面はprotocol=1 (master_key_00) でスキャン可能、protocol=3のフレームはスキップされる

### LDNパスフレーズ問題
- **現状**: 既知のパスフレーズは2タイトルのみ (kinnay/NintendoClients wiki LDN-Passphrases)
  - Mario Kart 8 Deluxe: `MarioKart8Delux` + 17 null bytes (タイトル短縮、32バイト固定長)
  - Super Mario Maker 2: `LunchPack2DefaultPhrase` (内部コードネーム `LunchPack` ベース)
- **パターン**: 一貫性なし（タイトル短縮 vs コードネーム）→ 推測困難
- **用途**: CCMP鍵導出 (server_random + passphrase) と認証ハンドシェイクに使用
  - パスフレーズを知らないとホスト・参加とも不可能（現アーキテクチャでは）
- **パスフレーズの技術的詳細** (Ryujinx + ldn_mitm ソースから確認):
  - `SecurityConfig` IPC構造体 (0x44 bytes):
    - `securityMode` (u16): 0=All, 1=Retail, 2=Debug
    - `passphraseSize` (u16): 最大64
    - `passphrase` (u8[64]): ゲーム固有の定数
  - ゲームは `nn::ldn::CreateNetwork` (IPC cmd 202) / `Connect` でこの構造体をシステムサービスに渡す
  - パスフレーズはゲーム側の定数 — エミュレータ/CFW sysmoduleはIPC傍受で取得
  - ソース: `upstream-ryujinx/src/Ryujinx.HLE/HOS/Services/Ldn/Types/SecurityConfig.cs`
  - ソース: `upstream-ldn-mitm/ldn_mitm/source/ldn_types.hpp`
- **パスフレーズ抽出方法**:
  - ゲームバイナリ (exefs/main.nso) にハードコードされている（MK8DX, SMM2 で確認）
  - NSP/XCI → hactool で exefs 展開 → main.nso 解凍 → バイナリ内文字列検索
  - `nn::ldn::CreateNetwork` に渡される SecurityConfig.passphrase として特定可能
  - ゲーム毎に一度の作業、結果は kinnay/NintendoClients wiki に貢献可能
  - 必要なもの: ゲームダンプ (NSP/XCI) + hactool + prod.keys
- **任意のゲームのパスフレーズ取得手順**:
  - 方法1 (推奨): Ryujinx にログ追加 — `IUserLocalCommunicationService.cs` の `CreateNetworkImpl` で
    `SecurityConfig` 読み取り直後にパスフレーズをログ出力。ゲーム起動→「ローカル通信」選択で取得。
    Switch不要、ゲームダンプのみ必要。.NETビルドなので環境構築も容易。
    対象箇所: `upstream-ryujinx/src/Ryujinx.HLE/HOS/Services/Ldn/UserServiceCreator/IUserLocalCommunicationService.cs:580`
  - 方法2: ldn_mitm にログ追加 — `ldn_icommunication.cpp` の `CreateNetwork` で `data.securityConfig` をログ出力。
    CFW Switch で実ゲームを起動して取得。対象箇所: `upstream-ldn-mitm/ldn_mitm/source/ldn_icommunication.cpp:65`
  - 方法3: 静的解析 — main.nso を Ghidra で解析、IPC cmd 202 のクロスリファレンスから特定。実行環境不要だが手間大
- **代替アプローチ: Raw フレームリレー**
  - LDNプロトコルに参加せず、802.11フレームを暗号化されたままトンネルする
  - パスフレーズ不要・全タイトル対応だが、実装が大きく異なる（monitor mode のみ使用）
  - 現アーキテクチャ (TAP bridge) とは互換性なし — 別実装が必要

### 2026-02-21: ELECOM WDC-867SU3SBK 検証
- A6210 の代替候補として入手・検証
- **チップ:** MT7612U (A6210と同一) — Manufacturer: MediaTek Inc.
- **USB ID:** `056e:400a` (Elecom Co., Ltd)
- **インターフェース名:** wlxbc5c4c16bc77, phy2
- **カーネルデバイステーブル未登録** — 手動バインドが必要:
  `echo "056e 400a" > /sys/bus/usb/drivers/mt76x2u/new_id`
- **iw list結果:** A6210と機能的に同等
  - AP, monitor, active monitor, frame コマンド全対応
  - 同時インターフェース制約も同一 (AP + monitor 可)
  - 2.4 GHz ch1-14 + 5 GHz ch36-177 — **デュアルバンド対応**
  - ELECOM公称「5 GHzのみ」はWindows向けマーケティング表記であり、ハードウェア的にはデュアルバンド
- **問題: TX power が極端に低い**
  - WDC-867SU3SBK: 2.4 GHz **5 dBm** (iw list報告値)
  - A6210: 2.4 GHz **18 dBm**
  - 差: 13 dB = 電力比約20倍
  - LDNスキャン: 密着状態でないとSwitchのネットワークを検出できず
  - 通常WiFiスキャン (iw scan) は23ネットワーク検出 — 受信は問題なし
  - 原因はTX powerの低さ (送信が弱すぎてSwitchとの双方向通信が成立しない)
- **技適認証 (204-430029):**
  - W52: 5180-5320 MHz (第19号の3)
  - W53/W56: 5500-5700 MHz (第19号の3の2)
  - **2.4 GHz帯のエントリなし** — 認証範囲外
  - TX power の低さは2.4 GHz送信を実質無効化する意図的なEEPROM設定
- **EEPROM TX power 解析:**
  - debugfs ダンプ: `/sys/kernel/debug/ieee80211/phyN/mt76/eeprom`
  - バックアップ済み: `eeprom_elecom.hex`, `eeprom_a6210.hex`
  - **参照コミット:** mt76 (openwrt/mt76) `9337d2f`
  - mt76x2 ドライバのソース解析結果:
    - `mt76x02_eeprom.h:42`: `MT_EE_TX_POWER_0_START_2G = 0x056`
    - `mt76x2/eeprom.c:361`: このオフセットから6バイト読み出し (tssi_slope, tssi_offset, **target_power**, delta x3)
    - `mt76x2/eeprom.c:365`: `t->chain[chain].target_power = data[2]` — 変換なしでそのまま代入
    - `mt76x2/init.c:194-196`:
      ```
      chan->orig_mpwr = mt76x02_get_max_rate_power(&t) + txp.target_power;
      chan->orig_mpwr = DIV_ROUND_UP(chan->orig_mpwr, 2);
      ```
      rate power + target_power の合計を **2で割って** dBm に変換 → iw 報告値
    - つまり **EEPROM の target_power は 0.5 dBm 単位**
  - ELECOM: offset `0x058` = `0x00` (target_power = 0) → ベース 0 dBm
  - A6210: offset `0x058` = `0x1e` (target_power = 30) → ベース 15 dBm
  - rate power delta が加算されて最終的な iw 報告値 (ELECOM: 5 dBm, A6210: 18 dBm) になる
- **EEPROM書き換えの調査:**
  - debugfs eeprom: パーミッション `0400` (読み取り専用)
    - `debugfs.c:118`: `debugfs_create_blob("eeprom", 0400, ...)` でハードコード (mt76@`9337d2f`)
  - USBベンダーリクエスト: `MT_VEND_READ_EEPROM` はあるが `MT_VEND_WRITE_EEPROM` は存在しない
    - `usb.c:87`: 読み出しは `MT_VEND_READ_EEPROM` 経由 (mt76@`9337d2f`)
    - ドライバはEEPROM書き込みをサポートしていない
  - USB初期化時: EEPROMデータをチップからカーネルメモリにコピー
    - `mt76x2/usb_init.c:110-119`: `mt76_rr(EEPROM, i)` → `eeprom.data` にコピー (mt76@`9337d2f`)
    - iw 報告値はこのメモリコピーから計算される
  - **書き換え対象:** offset `0x058` (chain 0) と `0x05e` (chain 1) を `0x00` → `0x1e` に
  - **ただし技適認証外の運用 = 電波法違反** — 電波暗室内でのみ検証可能
- **結論: LDN用途 (2.4 GHz AP) には現状使用不可** — 電波暗室での書き換え検証は技術的に可能
- **EEPROM 書き換え試行 (debugfs 経由) — 失敗:**
  - `debugfs.c:118` の eeprom パーミッションを `0400` → `0600` に変更して mt76.ko をリビルド
  - debugfs 経由で `eeprom.data` (カーネルメモリ) への書き込みには成功
  - しかし `iw phy` が報告する TX power は変化せず
  - **原因:** `chan->max_power` は `mt76x2_init_txpower()` (`mt76x2/init.c:188-203` @ v6.17.9)
    でドライバ初期化時に一度だけ計算・キャッシュされる。
    初期化後に `eeprom.data` を書き換えてもキャッシュは更新されない
  - debugfs 経由の書き換えでは、EEPROM 読み出し (`mt76x2u_init_eeprom`)
    → TX power 計算 (`mt76x2_init_txpower`) の間に介入できない
  - ロールバック: 全 mt76 モジュールを rmmod → modprobe で標準版に復帰
- **EEPROM 書き換え手順 (init_eeprom パッチ):**
  1. カーネルバージョン特定:
     ```
     cat /proc/version_signature
     ```
     → `Ubuntu 6.17.0-14.14~24.04.1-generic 6.17.9` (ベース: mainline v6.17.9)
  2. mt76 ソースの取得:
     ```
     cd $(mktemp -d) && pwd   # ビルドディレクトリを控える
     git clone --depth 1 --branch v6.17.9 --filter=blob:none --sparse \
       https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
     cd linux
     git sparse-checkout set drivers/net/wireless/mediatek/mt76
     ```
  3. パッチ適用 -- `drivers/net/wireless/mediatek/mt76/mt76x2/usb_init.c`:
     `mt76x2u_init_eeprom()` 内、EEPROM 読み出しループの直後に追加:
     ```diff
      	for (i = 0; i + 4 <= MT7612U_EEPROM_SIZE; i += 4) {
      		val = mt76_rr(dev, MT_VEND_ADDR(EEPROM, i));
      		put_unaligned_le32(val, dev->mt76.eeprom.data + i);
      	}
     +
     +	/* Override 2.4 GHz target_power: chain 0 and chain 1 */
     +	((u8 *)dev->mt76.eeprom.data)[MT_EE_TX_POWER_0_START_2G + 2] = 0x1e;
     +	((u8 *)dev->mt76.eeprom.data)[MT_EE_TX_POWER_1_START_2G + 2] = 0x1e;
     +
      	mt76x02_eeprom_parse_hw_cap(dev);
     ```
     - `MT_EE_TX_POWER_0_START_2G` = `0x056`, `MT_EE_TX_POWER_1_START_2G` = `0x05c`
       (`mt76x02_eeprom.h:42-43` @ v6.17.9)
     - `+2` で target_power バイトを指す (`eeprom.c:365` @ v6.17.9)
     - `eeprom.data` は `void *` なので `u8 *` にキャストが必要
     - 変更は `mt76x2u.ko` に含まれる (`usb_init.c` → `mt76x2u.o`)
  4. ビルド:
     ```
     make -C /lib/modules/$(uname -r)/build \
       M=$(pwd)/drivers/net/wireless/mediatek/mt76 \
       CONFIG_MT76_CORE=m CONFIG_MT76_USB=m \
       CONFIG_MT76x02_LIB=m CONFIG_MT76x02_USB=m \
       CONFIG_MT76x2_COMMON=m CONFIG_MT76x2U=m \
       modules
     ```
     - `-C` はカーネルヘッダの参照のみ、コンパイルは `M=` 側で実行される
     - BTF warning (vmlinux 不在) は動作に影響なし
  5. モジュール差し替え:
     `mt76x2u.ko` のみパッチ版を使い、他は標準モジュールをそのまま使う。
     ```
     # アンロード (依存の上流から順に)
     sudo rmmod mt76x2u
     sudo rmmod mt76x2_common
     sudo rmmod mt76x02_usb
     sudo rmmod mt76_usb
     sudo rmmod mt76x02_lib
     sudo rmmod mt76

     # 標準モジュールを再ロード
     sudo modprobe mt76
     sudo modprobe mt76_usb
     sudo modprobe mt76x02_lib
     sudo modprobe mt76x02_usb
     sudo modprobe mt76x2_common

     # パッチ済み mt76x2u.ko をロード (insmod でパスを直接指定)
     sudo insmod /tmp/tmp.1Um2wTlDd2/linux/drivers/net/wireless/mediatek/mt76/mt76x2/mt76x2u.ko
     ```
  6. ELECOM アダプタのバインド:
     ```
     echo "056e 400a" | sudo tee /sys/bus/usb/drivers/mt76x2u/new_id
     ```
  7. phy 番号の確認 (以降 `phyN` を置き換える):
     ```
     iw dev | grep -B1 wlxbc5c4c16bc77
     ```
  8. 効果確認:
     ```
     iw phy phyN info | grep "2412"
     ```
     TX power が 5.0 dBm から増加していれば成功。
  - **結果: `iw phy` 報告値 5 dBm → 20 dBm, `iw dev` txpower 20.00 dBm に変化**
  - **しかし実動作は変化なし** — 依然として密着状態でのみスキャン可能
  - **結論: ハードウェアの物理的制約。** ドライバが TX power レジスタに 20 dBm を書き込んでも、
    2.4 GHz 用パワーアンプ (PA) が未搭載または無効化されているため、実際の RF 出力は変わらない。
    EEPROM `target_power = 0` はソフトウェア制限ではなく、ハードウェア実態を反映した値。
    技適認証 (204-430029) に 2.4 GHz エントリがないことと一致する
  - **ELECOM WDC-867SU3SBK は LDN 用途に使用不可 (確定)**
  - この書き換えはカーネルメモリ上のみ。チップの EEPROM には書き込まない
  - モジュール再ロードまたはアダプタ抜き差しで元に戻る (パッチ版を再ロードすれば再適用)
  - ロールバック: `sudo rmmod mt76x2u && sudo modprobe mt76x2u`

### 2026-02-21: ENETDOWN 根本原因調査 (NEW_KEY on A6210)

PR #8 に対するメンテナ (kinnay) のコメントを受け、ENETDOWN の根本原因を再調査。
テスト: A6210 (mt76x2u) + 未パッチ upstream LDN @ `01259fe` → ENETDOWN 再現を確認。

**エラー発生箇所の特定 (カーネル v6.17.9):**
- `NL80211_CMD_NEW_KEY` は `NL80211_FLAG_NEED_NETDEV_UP` フラグ付き (nl80211.c:17674)
- generic netlink の `pre_doit` フック (`nl80211_pre_doit`, nl80211.c:17348) で
  `wdev_running(wdev)` をチェック (nl80211.c:17395-17398)
- `wdev_running()` → `netif_running(wdev->netdev)` → `__LINK_STATE_START` ビットを参照 (cfg80211.h:6659)
- `pre_doit` を通過しても、`ieee80211_add_key()` (cfg.c:526-527) が
  `ieee80211_sdata_running(sdata)` → `SDATA_STATE_RUNNING` ビットもチェック
- いずれかが false → `-ENETDOWN` (errno 100)

**矛盾: START_AP は成功する:**
- `NL80211_CMD_START_AP` も `NL80211_FLAG_NEED_NETDEV_UP` フラグ付き (nl80211.c:17697)
- START_AP 成功 = その時点ではインターフェースは running
- START_AP → NEW_KEY の間はマルチキャストイベント待機ループのみ (wlan.py:1600-1604)
- この間にインターフェースが down になる原因が不明

**`SDATA_STATE_RUNNING` の設定/解除箇所 (全3箇所):**
1. `iface.c:486` — `ieee80211_do_stop()` (インターフェース DOWN 時)
2. `iface.c:1265` — `ieee80211_del_virtual_monitor()` (仮想 monitor の sdata のみ、AP には影響なし)
3. `iface.c:1516` — `ieee80211_do_open()` エラーパス (`up()` 成功ならここに到達しない)

**mt76x2u ドライバ固有の調査:**
- `mt76x2u_ops` に `.start_ap` コールバックなし (usb_main.c:90-118)
  → `drv_start_ap()` は no-op (driver-ops.h:1088: `if (local->ops->start_ap)` → false → ret=0)
- `mt76x02_bss_info_changed()` (mt76x02_util.c:635-673): beacon/ERP 設定のみ、状態変更なし
- `mt76x02_add_interface()` (mt76x02_util.c:298-337): vif_mask 競合時のみ EBUSY
- インターフェース制約: `max_interfaces=2, num_different_channels=1` (mt76x02_util.c:79-87)
- `nl80211_key_allowed()` (nl80211.c:1607): AP モードは無条件 pass (line 1612-1616: `break`)

**根本原因: NetworkManager の race condition (確定):**

デバッグ logging を wlan.py に挿入し、各ステップで sysfs flags (`/sys/class/net/<name>/flags`) を確認:
```
[DEBUG] after up():              flags=0x1003 (UP) operstate=down
[DEBUG] after disable_ipv6():    flags=0x1003 (UP) operstate=down
[DEBUG] before START_AP request: flags=0x1003 (UP) operstate=down
[DEBUG] after START_AP ACK:      flags=0x1003 (UP) operstate=up
[DEBUG] received START_AP event: flags=0x1003 (UP) operstate=up
[DEBUG] before NEW_KEY:          flags=0x1003 (UP) operstate=up  ← まだ UP
[DEBUG] NEW_KEY failed: [Errno 100] Network is down
[DEBUG] after NEW_KEY failure:   flags=0x1002 (DOWN)             ← DOWN に変化
```
- sysfs 上は NEW_KEY 直前まで IFF_UP (0x1003) が設定されている
- しかしカーネルの NEW_KEY 処理時には既に DOWN → ENETDOWN
- sysfs 読み取りとカーネル処理の間の race window で NM がインターフェースを DOWN にしている

NM ジャーナルログが決定的証拠:
```
journalctl -u NetworkManager --since '30 minutes ago' | grep wlx94
```
```
device (wlx94a67e5d7030): driver supports Access Point (AP) mode
manager: (wlx94a67e5d7030): new 802.11 Wi-Fi device (/org/freedesktop/NetworkManager/Devices/30)
device (wlx94a67e5d7030): state change: unmanaged -> unavailable (reason 'managed', sys-iface-state: 'external')
device (wlx94a67e5d7030): state change: unavailable -> unmanaged (reason 'removed', sys-iface-state: 'removed')
```
- `_create_interface()` が AP インターフェースを作成すると NM が即座に検出
- `unmanaged → unavailable` 遷移時に NM がインターフェースを DOWN にする
- `up()` → START_AP → NEW_KEY の間にこの DOWN が差し込まれる (race condition)
- `reason 'removed'` は LDN のエラー処理がインターフェースを削除した結果

**修正と検証:**
```bash
sudo tee /etc/NetworkManager/conf.d/99-ldn-unmanaged.conf << 'EOF'
[device-ldn]
match-device=interface-name:wlx94a67e5d7030
managed=0
EOF
sudo systemctl reload NetworkManager
```
- NM を reload 後、upstream LDN コード (未パッチ) で host_test.py を実行 → **NEW_KEY 成功、AP 起動成功**
- Switch の「ローカル通信」画面から Linux PC のネットワークが見えることを確認
- operstate も `down → up` に正常遷移 (START_AP 内の `netif_carrier_on()` が反映)

**排除された仮説:**
1. ~~udev rename~~ — `ifname="wlx94a67e5d7030"` (MAC ベース名) を直接指定しても ENETDOWN 再現
2. ~~カーネル/ドライババグ~~ — NM 無効化で正常動作
3. ~~`netif_change_name()` による DOWN~~ — カーネルソース確認済み、rename は `dev_close()` を呼ばない

**PR #8 への影響:**
- **ENETDOWN の原因は NM interference であり、upstream LDN コードのバグではない**
- fork の NEW_KEY/SET_KEY 削除は NM 干渉の回避策であって正しい修正ではない
- メンテナ (kinnay) のコメント通り、鍵削除はコントロールポートフレームの暗号化を壊す
- 正しい対応: NM 管理外設定をドキュメントに追記 (または LDN コード内で `nmcli device set <ifname> managed no` を実行)
- Step 4 のパッチ要件を再評価する必要あり:
  - NEW_KEY/SET_KEY 削除 → **不要** (NM 修正で解決)
  - REGISTER_FRAME 順序変更 → 要再検証 (NM 修正後も必要か)

### 2026-02-21: GBAtempスレッド調査
- https://gbatemp.net/threads/local-wireless-play-over-internet.516675/ (2018年)
- 技術的に有用な情報なし。誰も実際には試していない
- OpenVPN TAP案はLANモードとLDNの混同に基づく
- kinnay/LDN以前の議論なので参考価値は低い
