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
- kinnay/LDN v0.0.16 の wlan.py に5つのパッチが必要（mt76x2u + kernel 6.17 対応）:
  1. `NL80211_ATTR_PRIVACY` フラグを `START_AP` 属性に追加
  2. `REGISTER_FRAME` を `START_AP` の前に移動（hostapd と同じ順序）
  3. グループ鍵 `NEW_KEY` を try/except（CCMP は Python 側 monitor で処理）
  4. デフォルト鍵 `SET_KEY` を try/except（同上）
  5. ステーション毎 `NEW_KEY` を try/except（同上）
- 根本原因: mt76x2u は START_AP 後のフレーム登録・鍵設定で ENETDOWN/EINVAL を返す
  - フレーム登録は START_AP 前に行えば成功
  - カーネルレベル CCMP 鍵は不要（monitor 経由で Python 処理のため）

### Step 5: TAPインターフェース確認 ★完了
- [x] ホスト中に `ldn-tap` が EN10MB (Ethernet) インターフェースとして存在
- [x] tcpdump でパケットキャプチャ可能を確認
- Linux PC自身の mDNS (169.254.109.1:5353 → 224.0.0.251) と IPv6 RS が流れている
- Switch からのゲームパケットは確認できず（Pia層認証なしのため即切断）
- TAPデータパスは正常動作 — トンネリングの基盤として十分

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

### 2026-02-21: GBAtempスレッド調査
- https://gbatemp.net/threads/local-wireless-play-over-internet.516675/ (2018年)
- 技術的に有用な情報なし。誰も実際には試していない
- OpenVPN TAP案はLANモードとLDNの混同に基づく
- kinnay/LDN以前の議論なので参考価値は低い
