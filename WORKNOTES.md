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
- [x] rfkill list, rfkill unblock 2 (ソフトブロック解除が必要だった)
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

### アーキテクチャ (v2: 参加者同期あり)
```
[Switch A] --LDN--> [PC A: APNetwork]
                        |
                     ldn-tap ←→ br-ldn ←→ gretap1
                                             |
                        TCP control channel + WireGuard
                                             |
                     ldn-tap ←→ br-ldn ←→ gretap1
                        |
[Switch B] --LDN--> [PC B: APNetwork]
```
- 両 PC とも `ldn.create_network()` で APNetwork を使用
  - `ldn.connect()` の STANetwork は TAP インターフェースを持たないため不可
  - APNetwork のみが TAP を作成し、Wi-Fi ↔ TAP のデータブリッジを行う
- GRETAP over WireGuard で TAP 間を L2 ブリッジ
- TCP 制御チャネルで参加者リストを同期

### v1 → v2 の設計変更理由
v1 は「両拠点が独立に LDN ホスト → TAP を L2 ブリッジ」の単純設計だった。
しかし以下の問題が判明:
1. **Pia が LDN 参加者リストに依存**: Pia（ゲーム通信層）は LDN アドバタイズメントの
   参加者リスト（IP/MAC）からピアを発見する。独立した LDN ネットワークでは
   対向の Switch が参加者リストに存在せず、Pia がピアを発見できない
2. **データ経路は正常**: TAP ↔ bridge ↔ GRETAP の L2 転送は問題なく機能する。
   `_transmit_data_frames` は peer チェックなしで TAP→Wi-Fi broadcast する
3. **制御平面の同期が必要**: 参加者リストの同期が必要 — データ平面は既に OK

### monkey-patch の設計 (kinnay/LDN v0.0.16 内部操作)
ライブラリの public API では参加者リスト操作・サブネット指定ができないため、
APNetwork の private 属性を直接操作する。

1. **`_network_id` 統一** (`__init__.py:1512`)
   - ライブラリは `random.randint(1, 127)` でサブネット ID を生成
   - 両 PC で同一値にしないと IP サブネット (169.254.X.0/24) が不一致
   - APNetwork 構築後、`start()` 前に上書き: `network._network_id = <shared>`
   - 参加者 IP は `169.254.{_network_id}.{index+1}` で算出 (`__init__.py:1739`)
   - TAP の IP も `169.254.{_network_id}.1` (`__init__.py:1781`)

2. **参加者インデックス分離** (`__init__.py:1732-1734`)
   - ライブラリは index 0 から順に空きスロットを探す
   - 両 PC が同じ index を使うと IP 衝突 (169.254.X.2 が両側に存在)
   - primary: index 1-3 (IP .2-.4)、secondary: index 4-6 (IP .5-.7) を使用
   - `_register_participant` を monkey-patch してインデックス範囲を制限

3. **仮想参加者注入** (制御チャネル経由)
   - 対向で Switch が JOIN → 制御チャネルで通知 → ローカルに仮想追加
   - `network._network.participants[index] = ParticipantInfo(...)` で直接書き込み
   - `network._update_nonce()` (`__init__.py:1675`) でアドバタイズメント更新
   - 次の 100ms 周期で新しい参加者リストがブロードキャストされる

### 制御チャネルプロトコル (TCP over WireGuard)
- Secondary が Primary の TCP ポート 39571 に接続
- JSON lines 形式 (1行 = 1メッセージ)
- メッセージ種別:
  - `PARAMS`: primary → secondary (ゲームパラメータ + network_id)
  - `READY`: secondary → primary (LDN ホスト準備完了)
  - `JOIN`: either → either (Switch 参加 {index, ip, mac, name})
  - `LEAVE`: either → either (Switch 離脱 {index})

### Step 1: tunnel_node.py v1 準備 ★完了 (v2 で置換)
- [x] `tunnel_node.py` v1 作成済み (単純な GRETAP + ホストのみ)

### Step 2: tunnel_node.py v2 実装 ★完了
- [x] 制御チャネル (TCP) 実装 — LineReader + JSON lines
- [x] monkey-patch (_network_id、_register_participant)
- [x] 仮想参加者注入 (inject/remove_virtual_participant)
- [x] GRETAP + bridge 構築 (setup/teardown_tunnel, add_tap_to_bridge)
- [x] 構文チェック・import 確認・CLI help 正常動作確認
- 実装上の発見:
  - `trio.BufferedByteStream` は存在しない → 独自 LineReader クラスで代替
  - `create_network()` の context manager は yield 前に `_initialize_network()` を
    実行するため、TAP IP は `_network_id` 上書き前のランダム値で設定される。
    `patch_network_id()` で `ip addr flush` + `ip addr add` による事後修正を追加
- 単拠点テスト結果 (--solo モード):
  - NM 管理外設定に `ldn` インターフェースの追加が必要だった
    (`make_create_param` で ifname 未設定 → デフォルト `"ldn"` → NM が管理しようとして ENETDOWN)
    `/etc/NetworkManager/conf.d/99-ldn-unmanaged.conf` に `interface-name:ldn` を追加
  - スキャン → ホスト → Switch 参加 (JoinEvent idx=1, IP=169.254.X.2) まで正常動作
  - Switch は参加後 2 秒で「通信エラー」→ Pia が participant 0 (PC) と UDP 通信を試みるが
    PC は Pia を話さないためタイムアウト。2拠点で Switch 同士が通信できれば解消する見込み
- **v2 の根本的欠陥が判明 → v3 へ移行** (後述)

### v2 → v3 の設計変更理由

v2 は両 PC が `create_network()` でホストする対称設計だが、以下の根本的欠陥がある:

1. **ゲームホスト問題**: PC が participant 0 (LDN ホスト) になるため、ゲーム進行権限も PC に渡る。
   MK8DX では部屋のホストがゲームモード・コースを選択するが、PC はゲームを実行していないため操作不能。
   Switch は両方とも「参加者」として入るため、誰もゲームを進行できない → デッドロック。
2. **パススルーではない**: 本来の目的は「ローカル通信の WAN 越えパススルー」。
   Switch A が部屋を作り、Switch B が WAN 越しにその部屋に参加する形にすべき。
   v2 は「PC が部屋を作り Switch が参加」であり、パススルーになっていない。

v3 では Switch A がホスト (部屋作成者) のまま、PC は透過的リレーとして動作する
非対称アーキテクチャに変更する。

### アーキテクチャ (v3: 非対称 STA + AP)
```
[Switch A: LDN ホスト (部屋作成)]       ← ゲーム進行の主導権
       ↕ Wi-Fi (LDN)
[PC A: connect() = STA として参加]      ← 透過リレー
   station IF ←→ br-ldn ←→ gretap1
                                ↕ WireGuard + TCP control
   ldn-tap ←→ br-ldn ←→ gretap1
[PC B: create_network() = AP プロキシ]  ← Switch A の部屋を複製
       ↕ Wi-Fi (LDN)
[Switch B: PC B の部屋に参加]           ← Switch A の部屋に参加した体験
```

- **Primary (PC A)**: `ldn.connect()` で Switch A の部屋に STA として参加
  - Station IF (managed mode) 1 つのみ。monitor/TAP なし
  - データはカーネル Wi-Fi スタック経由 (Python を介さない)
  - `_monitor_network()` で Switch A の advertisement 変更を監視
  - station IF を Linux bridge に追加し GRETAP 経由でトンネル
- **Secondary (PC B)**: `ldn.create_network()` で Switch A の部屋を複製した AP を起動
  - AP + monitor + TAP の 3 構成 (v2 と同じ)
  - participant 0 を Switch A の情報に書き換え → Switch B から見て Switch A がホスト
  - `application_data` を制御チャネル経由でリアルタイム同期

### v3 monkey-patch (PC B のみ)

1. **`_network_id` 統一**: Switch A のサブネット ID に合わせる
   - PC A が STANetwork の `_network_id` を取得 → 制御チャネルで送信
2. **participant 0 書き換え**: Switch A の情報 (IP, MAC, name) を設定
   - BSSID (PC B MAC) と participant 0 MAC は不一致だが問題なし
   - STA は自身の MAC で participant list を検索する (`__init__.py:1387-1389`)
3. **`_register_participant` パッチ**: Switch B を index 1+ に割り当て
4. **`application_data` 同期**: PC A → 制御チャネル → PC B が更新 + `_update_nonce()`

### v3 制御チャネルプロトコル
- `NETWORK`: PC A → PC B (Switch A の全状態: params, participants, network_id)
- `READY`: PC B → PC A (APNetwork 起動完了)
- `JOIN`/`LEAVE`: either → either (Switch 参加/離脱)
- `APP_DATA`: PC A → PC B (application_data 更新)
- `ACCEPT`: PC A → PC B (accept_policy 更新)

### v3 主要リスク
- Switch A の Pia が Switch B を認識しない可能性 (Switch B は Switch A の participant list に不在)
- 対策: まず試す → 失敗なら raw frame relay に移行

### Step 3: tunnel_node.py v3 実装 ★進行中
- [x] Primary: scan → connect() → bridge station IF → control channel
- [x] Secondary: receive params → create_network() → patch → bridge TAP
- [x] 構文チェック・CLI help 確認
- [x] 単拠点テスト (--solo) ★成功
- [x] 2拠点接続テスト ★ロビー参加確認
- [x] 再起動手順の改善 (while True accept ループ)
- [x] Pia 接続問題分析 → routing+NAT 設計
- [x] routing+NAT 実装 → テスト → 失敗 (gretap1: 0 packets, broadcast 転送不可)
- [x] bridge+tc mirred 改良版実装 (MAC learning 無効化)
- [x] 2拠点テスト: L2 パス動作確認 ★Pia セッション確立失敗
- [ ] v3 STA+AP の Pia 限界を克服する方法の検討

#### v3 実装詳細 (tunnel_node.py)

**v2 からの主要変更:**
- `run_primary`: `create_network()` → `connect()` (STA として Switch A に参加)
- `run_secondary`: participant 0 書き換え追加、`_register_participant` は index 1+ に制限
- 制御チャネル: `params` → `network` メッセージに拡張 (全参加者情報含む)
- 新メッセージ: `app_data` (ApplicationDataChanged 転送)、`accept` (AcceptPolicyChanged 転送)
- `patch_network_id` + `patch_register_participant` → `patch_secondary_network` に統合
- `add_station_to_bridge()` 追加 (Primary: station IF を bridge に追加)

**Primary (`run_primary`):**
1. `scan_mk8dx()` → Switch A の MK8DX 部屋を発見
2. `ldn.connect(param)` → STA として参加 (`ConnectNetworkParam` 使用)
3. `--solo`: イベント監視のみ (JoinEvent, ApplicationDataChanged, DisconnectEvent)
4. `--solo` なし: `setup_tunnel()` → `add_station_to_bridge("ldn")` → control channel
5. `make_network_msg(sta)` で STANetwork の全状態を Secondary に送信
6. `handle_primary_events`: ApplicationDataChanged/AcceptPolicyChanged を Secondary に転送
7. `handle_peer_messages_primary`: Secondary からの JOIN/LEAVE をログ記録 (注入不可)

**Secondary (`run_secondary`):**
1. `setup_tunnel()` → Primary に TCP 接続
2. `recv_msg()` で NETWORK メッセージ受信 → `make_create_param()` で CreateNetworkParam 構築
3. `ldn.create_network(param)` → AP ホスト
4. `patch_secondary_network()`:
   - `_network_id` = Switch A のサブネット ID (__init__.py:1512)
   - participant 0 = Switch A の情報 (IP, MAC, name) (__init__.py:1514-1521)
   - TAP IP = `169.254.{network_id}.1/24` (ip addr flush + add)
   - `_register_participant` monkey-patch: index 1-7 のみ使用 (__init__.py:1732-1734)
   - `_update_nonce()` でアドバタイズメント更新
5. `add_tap_to_bridge()` → READY 送信
6. `handle_secondary_events`: Switch B の JOIN/LEAVE を Primary に転送
7. `handle_peer_messages_secondary`: APP_DATA → `set_application_data()`、ACCEPT → `set_accept_policy()`

**--solo テスト結果:**
- コマンド: `sudo .venv/bin/python tunnel_node.py prod.keys --role primary --local 10.8.0.2 --remote 10.8.0.5 --phy phy1 --solo`
- スキャン: 2/10 で MK8DX 検出 (ch=1, proto=1, ver=4, app_ver=14, BSSID=5C:52:1E:EA:EB:9E)
- STA 参加成功: participant 1, network_id=25, IP=169.254.25.2
- Host (Switch A): IP=169.254.25.1, MAC=5C:52:1E:EA:EB:9E
- Ctrl+C まで安定接続 (v2 では 2 秒で Pia timeout → 通信エラーだったが、v3 では PC がホストでないため発生せず)
- Ctrl+C 時の ExceptionGroup は trio nursery 経由の正常な KeyboardInterrupt 伝播

**station IF ブリッジ問題と解決:**
- `ip link set ldn master br-ldn` → `Error: Device does not allow enslaving to a bridge.`
- managed-mode WiFi STA は mac80211 が bridge への追加を拒否する (EOPNOTSUPP)
- **解決: veth pair + tc mirred redirect**
  - `relay-sta` ↔ `relay-br` の veth pair を作成
  - `relay-br` を bridge に追加
  - `tc ingress redirect` で station IF ↔ relay-sta を双方向リダイレクト
  - パケット経路: Switch A → [ldn] →(tc)→ [relay-sta] →(veth)→ [relay-br] → bridge → gretap1

**ファイアウォール設定:**
- Primary 側で TCP 39571 (制御チャネル) を WireGuard サブネットから許可する必要あり
- `sudo ufw allow from 10.8.0.0/24 to any port 39571 proto tcp`

**ENOTUNIQ エラーの根本原因 (セカンダリ、解決済み):**
- 症状: `create_network()` → `self.up()` → `RTM_NEWLINK` (IFF_UP) が `OSError: [Errno 76] Name not unique on network` を返す
- ライブラリの問題ではない。手動 `iw phy phy2 interface add test-ap type __ap && ip link set test-ap up` でも再現
- 根本原因: S3 サスペンド/レジューム時に xHCI コントローラがエラー (`USBSTS 0x401, Reinit`)
  → mt76x2u ドライバの内部状態が壊れ、AP インターフェースを UP できない状態に
- 修正: A6210 を USB から物理的に抜き差し → ファームウェアとドライバが完全再初期化
  → phy 番号が phy2 → phy3 に変更され、正常動作に復帰
- 予防: サスペンド後は必ず A6210 を USB 抜き差し (または `rmmod mt76x2u && modprobe mt76x2u`)
- セカンダリの NM 管理外設定: `/etc/NetworkManager/conf.d/99-ldn-unmanaged.conf` に
  `interface-name:wlx*;interface-name:ldn` を設定済み

**2拠点接続テスト結果:**
- ロビー参加成功: Switch B が PC B の部屋に参加し、Switch A がホストするロビーを確認
  - Switch B: idx=1, IP=169.254.{nid}.2, MAC=64:B5:C6:1B:14:9B
- **Pia 通信失敗**: ゲーム開始 (対戦開始) 時に「通信相手からの応答がありませんでした」
  - Switch B がロビーから強制退出される
  - ロビー内の操作 (キャラ選択等) は正常 — LDN 層は機能している
  - Pia 層 (UDP 直接通信) の確立に失敗

**再接続サポート (解決済み):**
- 問題: セカンダリ Ctrl+C 後の再起動で Connection refused
- 原因: Primary が TCP listener を最初の accept 後に閉じていた
- 修正: `run_primary` を `while True` accept ループに変更、listener は finally で閉じる
- nursery cancel で前の secondary セッションを安全に終了

#### Pia 通信失敗の根本原因分析

**3つの問題が同時に存在:**

1. **IP 衝突**: PC A (participant 1) と Switch B (participant 1 on secondary) が
   両方 `169.254.{nid}.2` を使用。_register_participant の index 範囲が 1-7 で
   Switch B が index 1 に入るため、Primary 側の PC A と同じ IP になる。

2. **MAC 書き換え**: managed-mode STA (ldn IF) は送信時に 802.11 Address 2 を
   自身の MAC に書き換える。bridge 経由で Switch B の MAC を持つフレームが入っても、
   実際に Switch A が受信する 802.11 フレームの source は PC A の MAC になる。
   → Switch A の Pia は Switch B からのパケットを識別できない。

3. **Switch A が Switch B を知らない**: Switch A の participant list には PC A しかいない。
   STANetwork は read-only であり、仮想参加者の注入は不可能。
   Pia は participant list から通信先の IP/ポートを発見するため、
   Switch B の情報がないと Pia セッション確立が成立しない。

**解決策: routing + iptables NAT (Primary 側)**

bridge + tc mirred + veth pair を全廃止し、gretap1 と ldn IF 間を
IP routing + iptables MASQUERADE で接続する。

核心アイデア: Switch B → Switch A の通信を PC A に成りすまさせる (MASQUERADE)。
Switch A の Pia は PC A (participant 1) との通信として認識する。
応答は conntrack の逆変換で Switch B に戻る。

**新データ経路:**
```
Switch B → PC B (WiFi) → TAP → br-ldn → gretap1 → WireGuard
  → PC A gretap1 (src=.3, dst=.1) → ip_forward → MASQUERADE (src→.2)
  → ldn IF → kernel 802.11 → Switch A

Switch A → ldn IF (src=.1, dst=.2) → conntrack reverse (dst→.3)
  → ip rule table 100 → gretap1 → WireGuard
  → PC B gretap1 → br-ldn → TAP → library broadcast → Switch B
```

**IP アドレス割り当て変更:**
| 参加者 | Index | IP |
|---|---|---|
| Switch A (ホスト) | 0 | 169.254.{nid}.1 |
| PC A (STA) | 1 | 169.254.{nid}.2 |
| Switch B | 2 | 169.254.{nid}.3 |

**必要な変更:**
- Primary: gretap1 standalone (bridge 不要) + ip_forward + MASQUERADE + policy routing
- Secondary: _register_participant range 2-7 (index 1 = PC A 用に予約)
- Secondary: TAP IP を .254 に変更 (Switch A 宛て通信を横取りしない)
- Secondary: participant 1 (PC A) を非表示 (Switch B に PC A を見せる必要なし)

#### routing+NAT 実装と失敗 (廃止)

routing+NAT を実装しテストしたが、以下の根本的欠陥により廃止:

**tcpdump 診断結果:**
- `gretap1` (Primary): **0 packets** — トンネルにデータが一切流れていない
- `ldn` (Primary): Switch A の Pia broadcast のみ
  `169.254.22.1:12345 → 169.254.22.255:12345 UDP 196 bytes (~100ms)`
  Switch A は Pia LAN ディスカバリを活発に送信しているが、gretap1 には転送されない

**根本的欠陥:**
1. **IP routing はブロードキャストを転送しない**: Switch A の Pia broadcast (.255 宛て) は
   カーネルがローカル配信として処理し、gretap1 にフォワードされない。
   Pia セッション確立にはブロードキャスト受信が必須。
2. **proxy_arp の in_dev 問題**: gretap1 に IP を付与しないと ARP 処理用の `in_dev`
   構造体が存在せず、proxy_arp が機能しない可能性。
   IP を付与すると ldn IF と重複ルートが発生し proxy_arp が壊れる。
3. **Pia ペイロードのミスマッチ**: MASQUERADE は IP ヘッダの src を書き換えるが、
   Pia UDP ペイロード内の送信者情報は書き換えない。
   Switch A の Pia はヘッダとペイロードの不一致を検出する可能性。

**結論:** routing+NAT は LDN/Pia の要件に根本的に適合しない。
L2 ブロードキャストを自然に扱える bridge+tc mirred に回帰する。

#### bridge+tc mirred 改良版 (MAC learning 無効化)

routing+NAT の失敗を受け、bridge+tc mirred に回帰。
ただし旧 bridge+tc mirred にも問題があったため改良:

**旧 bridge+tc mirred の問題:**
- ブロードキャストは正常に転送される (ロビー動作)
- **ユニキャスト復路が失敗**: Switch A が PC A の MAC 宛てに送信
  → bridge が PC A の MAC を relay-br ポートで学習済み
  → 同一ポートへの転送なし → gretap1 に到達しない → Switch B に届かない

**修正: bridge ポートの MAC learning 無効化**
```
bridge link set dev relay-br learning off
bridge link set dev gretap1 learning off
```
- learning off → すべてのフレームが全ポートにフラッディング
- bridge ポートが 2 つのみ (relay-br + gretap1) → フレームは到着ポートに戻らないためループなし
- Switch A → ldn → tc mirred → bridge → gretap1 → tunnel → Switch B (ユニキャストも通過)

**Switch B の participant index:**
- index 1 (IP .2, PC A と同一) に戻す
- MAC 書き換え (ldn IF managed mode) + 同一 IP により、
  Switch A の Pia は Switch B の通信を PC A からのものとして認識
- index 2 (IP .3) では Switch A の participant list に .3 が存在せず Pia が reject

**TAP IP:**
- .254 を維持 (旧 .1 ではなく)
- .1 = Switch A の IP → TAP が ARP を横取りしてトンネル経由の通信を阻害
- .254 は participant IP 範囲外で安全

#### bridge+tc mirred 改良版 実装 (2026-02-23)

routing+NAT コードを全廃止し、bridge+tc mirred に回帰 + MAC learning 無効化を追加。

**tunnel_node.py 変更内容:**

1. **`setup_tunnel_primary` / `setup_tunnel_secondary` → 共用 `setup_tunnel`**
   - Primary/Secondary 両方が gretap1 + br-ldn を使用
   - routing+NAT では Primary が gretap1 standalone だったが廃止

2. **`setup_primary_routing` → `setup_station_relay` 復元 + MAC learning 無効化**
   - veth pair (relay-sta ↔ relay-br) + tc mirred redirect を復元
   - 新規: `bridge link set dev relay-br learning off` + `bridge link set dev gretap1 learning off`
   - routing+NAT の proxy_arp / ip_forward / MASQUERADE / FORWARD / policy routing を全廃止

3. **`teardown_primary` / `teardown_secondary` → 共用 `teardown_tunnel`**
   - tc qdisc del + veth 削除 + bridge 削除 + gretap1 削除

4. **`_register_participant` index 範囲: `range(2, 8)` → `range(1, 8)` に復元**
   - Switch B を index 1 (IP .2) に配置 = PC A と同一 IP
   - Switch A の Pia が PC A からの通信として認識する

5. **TAP IP .254 は維持** (routing+NAT で導入、有効なため継続)

6. **`run_primary` / `run_secondary` 更新**
   - `setup_tunnel_primary` → `setup_tunnel` + `setup_station_relay`
   - `teardown_primary("ldn", network_id)` → `teardown_tunnel()`
   - `setup_tunnel_secondary` → `setup_tunnel`
   - `teardown_secondary()` → `teardown_tunnel()`

7. **`cleanup_stale_interfaces` の iptables 清掃は維持** (routing+NAT 残骸対策)

#### bridge+tc mirred 改良版テスト結果 (2026-02-23)

**L2 データパスは完全に動作:**

tcpdump 診断 (Primary 側、gretap1 / br-ldn / ldn の 3 インターフェース):
- **gretap1**: Switch A の Pia broadcast (196 bytes) と Switch B の Pia broadcast (84 bytes) の両方が流れている
- **br-ldn**: 同上 (bridge 経由で両方向通過)
- **ldn**: Switch A の broadcast (RX) と Switch B の broadcast (TX, tc redirect 経由) の両方が確認

データパス確認:
- ✅ Switch A (.1) → ldn RX → tc mirred → bridge → gretap1 → tunnel → Secondary (196 bytes, ~100ms)
- ✅ Switch B (.2) → Secondary TAP → gretap1 → tunnel → Primary bridge → tc mirred → ldn TX → Switch A (84 bytes)
- ❌ ユニキャスト通信: `.1 → .2` も `.2 → .1` も **0 件**

**問題は Pia プロトコル層:**

両側の Pia broadcast discovery は互いに到達しているが、Pia セッション確立 (unicast) に移行しない。
- Switch A の Pia: participant 1 (PC A) との Pia handshake を期待
- PC A: ゲーム非実行 → Pia 状態なし → handshake に応答できない
- Switch B の broadcast: PC A の IP (.2) から届くが、Pia ペイロード内の
  セッション識別子が PC A の Pia 状態と不一致 → Switch A の Pia が無視
- パケットサイズの違い (Switch A: 196 bytes, Switch B: 84 bytes) も
  異なる Pia メッセージ型であることを示唆

**結論:** v3 STA+AP アーキテクチャの根本的限界。
PC A が Pia プロトコルに参加できないため、Switch A は PC A (participant 1) との
Pia セッションを確立できず、Switch B の通信も Pia レベルで受理されない。
L2 データパスは完璧に動作しているが、Pia の application-level handshake が成立しない。

#### Pia プロトコル分析 (2026-02-23)

**参照ソース:** https://github.com/kinnay/NintendoClients.wiki.git

**Pia 通信の仕組み (LDN モード):**

1. **発見**: LDN advertisement frame の application_data にセッション情報 (session_id, session_param)
2. **セッション鍵**: session_param を SEAD RNG で展開 → AES(game_key) で暗号化 → 16 byte session key
3. **Pia パケット (5.27-5.45)**: Magic `32 AB 98 64` + header (dst/src variable_id, packet_id, nonce, tag) + AES-GCM encrypted messages + footer
4. **AES-GCM nonce (LDN)**: `CRC32(session_id + source_MAC)[0:3] + source_variable_id[0:1] + header_nonce[0:8]`
5. **mesh 参加フロー**: 発見 → connection request (Station Protocol 0x14) → join request (Mesh Protocol 0x18) → join response → mesh update → 全ノード接続確立

**根本原因の詳細分析 — 2 つの問題:**

**問題 1: LDN-Pia tight coupling**
- LDN ホスト (Switch A) が participant list を管理し、新規参加時に Pia 層に通知
- Switch B は Secondary の AP に参加 → Switch A の LDN 層は Switch B を認知しない
- → Switch A の Pia は mesh joining を開始しない
- → Switch B の connection request は受理されない (unknown peer)

**問題 2: MAC 書き換えによる nonce 不一致**
- Pia の AES-GCM nonce に CRC32(session_id + **source_MAC**) が含まれる
- managed-mode STA は送信時に source MAC を PC A の MAC に書き換える
- Switch B の Pia: CRC32(session_id + **Switch_B_MAC**) で暗号化
- Switch A の Pia: participant .2 = PC A → CRC32(session_id + **PC_A_MAC**) で復号試行 → 不一致 → 復号失敗
- たとえ L2 パスが動作しても、暗号化レイヤーで必ず失敗する

**問題 3: IP 衝突 (副次的)**
- PC A と Switch B が同一 IP (.2) → Switch A の participant lookup が PC A の MAC を返す

**Pia プロトコルのリレー関連機能:**
- Station Protocol: message type 6/7 = Relay connection request/response
- Message flags: 0x2 = "needs relay to single console", 0x4 = "needs relay to multiple", 0x8 = "was relayed"
- Mesh Protocol: message type 0x81 = "Relay route directions"
- → Pia にはリレー機構が組み込まれているが、NEX (オンライン) モード用と推測。LDN で使えるかは不明

**MK8DX のゲーム鍵:** `ABCDEFGHIJKLMNOP` (Pia-Game-Keys.md)

**検討中のアプローチ:**

| アプローチ | 概要 | 利点 | 課題 |
|---|---|---|---|
| **A. Pia パケット翻訳** | UDP 層で Pia パケットを傍受、復号→nonce 変更→再暗号化 | L2 パスは既存を利用 | mesh 参加問題は未解決。variable_id 不明→peer 不明→パケット破棄。ゲーム鍵が必要 |
| **B. LDN 認証注入** | monitor mode で 802.11 auth + LDN auth frame を注入。Switch B の MAC で Switch A の AP に直接参加 | MAC 問題を根本解決。Switch A が Switch B を participant として認識 | LDN 認証チャレンジ (HMAC-SHA256, device_id) の実装が必要。data frame 暗号化の取り扱い |
| **C. 2 つ目の STA** | PC A に 2 つ目の managed IF (ldn2) を Switch B の MAC で追加、同じ AP に参加 | カーネルが暗号化を処理 | LDN 認証チャレンジ (ゲーム購入検証) のバイパスが必要。mac80211 multi-STA 対応 |
| **D. LAN モード** | MK8DX の LAN モード (L+R+Left Stick) を使用。nonce に MAC でなく IP を使用 | 大幅に単純。bridge+tunnel だけで動く可能性 | ゲーム側の操作変更が必要。全ゲーム対応ではない |

### アーキテクチャ (v4: MAC スプーフ STA リレー)

v3 の根本的限界 (Pia がPC A を認識できない) を解決するため、
**PC A が Switch B の MAC で Switch A の AP に参加する** 方式に変更。

```
[Switch A: LDN ホスト (部屋作成)]
       ↕ Wi-Fi (LDN)
[PC A: connect(address=Switch_B_MAC) = STA として参加]
   station IF ←→ bridge ←→ gretap1
                              ↕ WireGuard + TCP control
   ldn-tap ←→ bridge ←→ gretap1
[PC B: create_network() = AP プロキシ]
       ↕ Wi-Fi (LDN)
[Switch B: PC B の部屋に参加]
```

**核心アイデア:** PC A の STA インターフェースに Switch B の MAC を設定。
- Switch A の LDN は Switch B が直接参加したと認識 → participant list に Switch B が登録される
- managed-mode STA は送信時に source MAC = Switch B の MAC で送出
- Pia AES-GCM nonce: CRC32(session_id + Switch_B_MAC) が一致 → 暗号化通信が透過的に成立
- constant_id, service_variable_id も Switch B の MAC から導出 → 完全一致

**フロー:**
1. Primary: scan → NETWORK 情報取得 (**STA 接続はまだしない**)
2. Primary: GRETAP tunnel + bridge 構築 → Secondary TCP 接続待機
3. Secondary: NETWORK 受信 → AP 起動 → patch → READY 送信
4. Switch B が Secondary の AP に参加 → JOIN (MAC) を Primary に送信
5. Primary: **Switch B の MAC で STA 接続** → relay 構築
6. Pia 通信が Switch A ↔ relay ↔ tunnel ↔ Switch B で透過的に成立

**v3 との主な違い:**
- scan 結果 (NetworkInfo) から NETWORK メッセージを生成 (STA 接続不要)
- STA 接続を Switch B の JOIN 受信まで遅延 (MAC が必要なため)
- ldn ライブラリに MAC スプーフ機能を追加 (ConnectNetworkParam.address)

### v4 ldn ライブラリ変更 (MAC スプーフ)

**フォーク:** https://github.com/u1f992/LDN.git (upstream: kinnay/LDN v0.0.16)
- `pyproject.toml` でコミットハッシュ指定 → `uv sync` で展開。手動パッチ不要
- ライブラリの修正が必要な場合はこのフォークを操作し、コミットハッシュを更新する

kinnay/LDN v0.0.16 に以下の最小変更を追加:

**1. `wlan.py` — `Factory.connect_network()` に `address` パラメータ追加**
- MAC アドレス変更は `update_link()` (route netlink RTM_NEWLINK) で IF が DOWN の間に実施
- `Station.connect()` が `up()` → `_connect_network()` を呼ぶ前に MAC を設定

**2. `__init__.py` — `ConnectNetworkParam` に `address` フィールド追加**
- `address: MACAddress | None = None` をデータクラスに追加
- `ldn.connect()` が `factory.connect_network()` に `param.address` を渡す

### v4 tunnel_node.py 変更

**新規・変更関数:**
- `make_network_msg_from_scan(info)`: scan 結果の NetworkInfo を NETWORK メッセージに変換
  - host IP (169.254.X.1) から network_id を抽出
  - 8 participant エントリにパディング
- `handle_primary_events(sta, peer_stream, relay_mac)`: relay_mac (= Switch B MAC) を追加
  - 自身の JoinEvent (spoofed MAC) をフィルタして Secondary に転送しない
- `handle_peer_messages_primary(reader)`: 簡略化。LEAVE で break (nursery cancel)

**`run_primary()` フロー変更:**
1. scan → NetworkInfo 取得 (STA 接続しない)
2. setup_tunnel + bridge
3. TCP listen → Secondary 接続待機
4. `make_network_msg_from_scan(info)` で NETWORK 送信
5. READY 待機
6. **JOIN 待機** → Switch B の MAC 取得
7. `ldn.connect(param)` with `param.address = ldn.MACAddress(switch_b_mac)`
8. `setup_station_relay()` → event loop

**`run_secondary()` は v3 と同一** (変更なし)。

### v4 テスト結果 (1回目) と修正

**テスト結果: ロビー参加成功、ゲーム開始時「通信相手からの応答がありませんでした」**

tcpdump 分析で 3 つの問題を特定:

**問題 1 (致命的): `_process_data_frame` の Ethernet dst マッピングバグ**
- `__init__.py:1852` で `header.target = frame.target` (Address 1 = BSSID for ToDS)
- 正しくは `header.target = frame.bssid` (Address 3 = DA for ToDS)
- 結果: Switch B の unicast が全て dst = AP MAC (PC B) として TAP に書き込まれる
- bridge が local delivery と判断 → gretap1 に到達せず → tunnel を通過しない
- **tcpdump 証拠**: `b-tcpdump-ldn-tap.log` にユニキャスト存在、`b-tcpdump-gretap1.log` にユニキャスト不在

**問題 2: IP 不一致 (潜在的)**
- Switch A が spoofed STA に割り当てた IP と Secondary が Switch B に割り当てた IP が
  異なる場合、Pia participant lookup が失敗
- クリーンな状態 (Switch A の部屋を新規作成) なら両方 index 1 (.2) に一致するはず

**問題 3 (軽微): Primary の LEAVE 自動終了**
- `handle_peer_messages_primary` が LEAVE で break → nursery cancel → Primary 終了
- Switch B が離脱しただけで Primary も終了してしまう

**修正内容:**

1. **ldn ライブラリ修正** (`ldn.patch` 更新):
   - `_process_data_frame`: `header.target = frame.target` → `header.target = frame.bssid`
   - ToDS の Address 3 (DA) を Ethernet dst に正しくマッピング

2. **CONNECTED メッセージ追加** (`tunnel_node.py`):
   - Primary: STA 接続後に `{"type":"connected", "index":N, "ip":"..."}` を Secondary に送信
   - Secondary: 受信して Switch B の IP と一致確認、不一致なら WARNING ログ

3. **LEAVE 自動終了の廃止** (`tunnel_node.py`):
   - `handle_peer_messages_primary`: LEAVE で break せず、ログ記録のみ
   - TCP 切断時のみ return → nursery cancel

### v4 テスト結果 (2回目): Station was disassociated

- Primary: `ConnectionError: Station was disassociated` at `__init__.py:1383`
- 802.11 接続は成功したが、LDN 認証中に AP (Switch A) が STA を disassociate
- 仮説: 同一チャネル (ch 11) で Secondary AP と Switch A の AP が動作
  → Switch A が同一 MAC を検出して disassociate
- 修正: `pick_secondary_channel()` で非重複チャネルを選択

### v4 テスト結果 (3回目): Connect failed with status code 1

- Primary: `ConnectionError: Connect failed with status code 1` (WLAN_STATUS_UNSPECIFIED_FAILURE)
- Secondary: `BrokenPipeError` (Primary TCP 切断の結果)
- チャネル分離後も失敗。エラーレベルが LDN 認証 → 802.11 接続に退行
- tcpdump: 全インターフェースでゲームトラフィック 0 件。`a-tcpdump-ldn.log` = "No such device exists"
- Switch A の AP が Association Response で status 1 を返している

**分析:**
2回のテストで異なるエラーモード (disassociation vs connect failure) が出現。
MAC スプーフ接続が不安定な原因として最も可能性が高いのは **scan → connect 間のタイムラグ**:
- scan 時点の NetworkInfo (server_random 等) が数分後の connect 時に古くなっている可能性
- solo mode は scan 直後に connect するため成功する
- v4 は tunnel 構築 + Secondary 待機 + Switch B JOIN 待機の間に分単位の遅延が発生

**修正: connect 直前に再スキャン + リトライ**
- `run_primary()` で connect 前に `scan_mk8dx()` を再実行して最新の NetworkInfo を取得
- ConnectionError 発生時は最大 3 回リトライ (2 秒間隔、毎回再スキャン)

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
- **PR #8 は CLOSED** — NM が根本原因と確認され、upstream の README に NM 管理外設定が追記済み

**ローカルパッチの清掃 (2026-02-22):**
- `.venv` 内の `wlan.py` に Phase 1 の REGISTER_FRAME 順序変更パッチが残存していた
  - `_register_frame()` 呼び出しを `_start_ap()` の前に移動するパッチ
  - PR #8 が CLOSED になり、upstream コードで NM 管理外設定のみで動作することが確認済み
  - → パッチは不要
- `.venv` を削除し `uv sync --no-cache` でクリーン再構築
- upstream ldn 0.0.16 未パッチ状態で `--solo` テスト → スキャン・ホスト・Switch 参加すべて正常動作
- **結論: ライブラリへのパッチは一切不要。NM 管理外設定のみで十分**

### 2026-02-21: GBAtempスレッド調査
- https://gbatemp.net/threads/local-wireless-play-over-internet.516675/ (2018年)
- 技術的に有用な情報なし。誰も実際には試していない
- OpenVPN TAP案はLANモードとLDNの混同に基づく
- kinnay/LDN以前の議論なので参考価値は低い
