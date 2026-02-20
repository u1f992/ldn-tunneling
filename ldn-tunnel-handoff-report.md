# Nintendo Switch ローカル通信（LDN）インターネットトンネリング — 開発ハンドオフレポート

## 1. プロジェクト概要

**目的:** ノーマル（未改造）のNintendo Switch同士で、インターネット越しにローカル通信（LDN: Local Device Network）を実現する。

**制約:**
- CFW（カスタムファームウェア）は使用しない — 両方のSwitchはノーマルのOFW
- Linux PCを中継ノードとして使用する
- 既存のWireGuard VPNを拠点間ブリッジに活用する

---

## 2. LDNプロトコルの技術的特性

### 2.1 概要
- LDNはNintendo Switchの「ローカル通信」機能で使用される独自の無線プロトコル
- IEEE 802.11のデータリンク層で動作する（IPレベルではない）
- LANモード（有線LAN経由の通信）とは完全に別物
- 対応ゲームは198タイトル以上（LANモード対応は約25タイトルのみ）

### 2.2 プロトコル詳細
- **公式ドキュメント:** https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol
- ホストがAPとして動作し、100ms間隔でベンダー固有のアクションフレームをブロードキャスト（アドバタイズメント）
- スキャン側のdwell time: 110ms
- SSIDは32桁のランダム16進数、ビーコンフレームではSSIDがゼロ化されて隠蔽
- 使用チャネル: 2.4GHz帯の7チャネルのうち1つ（ゲームが指定可能、デフォルトはランダム選択）

### 2.3 認証フロー
1. クライアントがopen system認証でネットワークに参加（標準的な802.11手順）
2. クライアントが暗号化された認証リクエストをAPに送信
3. **5秒以内**に認証リクエストが届かない場合、APがクライアントを切断
4. LDN version 3以降ではチャレンジ機構あり（ゲーム購入の検証用）
5. 認証トークンはネットワーク作成時に生成

### 2.4 データ通信
- 認証後、ゲームはBSDサービス経由でUDPソケットを開き、LDNサービスが提供するIP/MACアドレスで他クライアントと通信
- データフレームのethertype: 0x88B7（OUI extended）、通常は暗号化される
- ホストからのフレームはFromDS有効、他ステーションからのフレームはFromDS/ToDS共に無効

---

## 3. コアライブラリ: kinnay/LDN

### 3.1 基本情報
- **リポジトリ:** https://github.com/kinnay/LDN
- **ライセンス:** GPL-3.0
- **言語:** Python 100%
- **インストール:** `pip install ldn`
- **要件:** Linux, Python 3.8+, モニターモード+アクションフレーム送受信対応のWi-Fiアダプタ
- **権限:** CAP_NET_ADMIN（rootで実行が最も簡単）
- **Discord:** https://discord.gg/x8np6Hhxwk

### 3.2 機能
- 近傍のLDNネットワークをスキャン
- LDNネットワークに参加
- LDNネットワークをホスト

### 3.3 内部アーキテクチャ（重要）
kinnay/LDNのREADMEにある「Design Considerations」より:

- LDNプロトコルはアドホックでもインフラストラクチャでもない中間的な方式
- ネットワーク参加後、全ノードが直接通信可能
- **ホスト実装にはAPモード+モニターモードの組み合わせを使用:**
  - 管理フレーム（probe request, association request等）→ APインターフェースで処理
  - データフレーム（ブロードキャスト宛含む）→ モニターモードインターフェースで送受信
  - APモードだけではブロードキャストアドレス（ff:ff:ff:ff:ff:ff）宛フレームがカーネル/ドライバにドロップされるため
  - IBSSモードもassociation requestがドロップされるため不可
- **データフレームはパース・復号されてTAPインターフェースに書き込まれる** ← トンネリングの鍵

### 3.4 既知の問題（Common Issues wikiより）
- https://github.com/kinnay/LDN/wiki/Common-Issues
- NetworkManagerとの干渉 → `sudo service NetworkManager stop` が必要
- **#7が最重要:** 一部のWLANドライバがネットワーク参加後にブロードキャスト宛アクションフレームを破棄する問題。ドライバ依存。
- **#5:** ドライバがmonitor/station/APモードをサポートしていない場合はOSError

---

## 4. ハードウェア

### 4.1 使用予定のWi-Fiアダプタ: Netgear A6210（第一候補）
- **チップセット:** MediaTek MT7612U
- **Linuxドライバ:** カーネル標準 `mt76x2u`（推奨、旧ベンダードライバは非推奨）
- **対応モード（iw listで確認済み事例）:**
  - IBSS, managed, AP, AP/VLAN, monitor, mesh point, P2P-client, P2P-GO
  - active monitor（受信フレームにACKを返す）対応
- **kinnay/LDNが必要とするAP + monitorの組み合わせに対応している見込み**
- 注意: 5GHz帯でDFSチャネル問題の報告あり（LDNは2.4GHz帯なので問題なし）

### 4.2 予備: エレコム WDC-867SU3SBK
- **チップセット:** Realtek RTL8812AU or RTL8812BU系（要確認）
- Realtekドライバはモニターモード/アクションフレーム対応が不安定な傾向
- A6210で問題が出た場合の予備として保持

### 4.3 Linux PC
- 両拠点にLinux PCあり（詳細スペック未確認）
- 有線LANでインターネット接続を確保し、Wi-Fiアダプタ（A6210）はLDN専用にする構成

---

## 5. ネットワーク構成

### 5.1 既存インフラ
- 両拠点間にWireGuard VPNが構築済み

### 5.2 提案アーキテクチャ

```
[Switch A] ←─ LDN (802.11) ──→ [Linux PC A]
                                    │
                                    ├── Wi-Fi: A6210 (mt76x2u)
                                    │     └── kinnay/LDN → TAPインターフェース
                                    │
                                    ├── bridge (br0)
                                    │     ├── tap-ldn (kinnay/LDNが作成)
                                    │     └── gretap0 or vxlan0
                                    │
                                    ├── WireGuard (wg0) ← 既存
                                    │
                                    └── 有線LAN (eth0) → インターネット
                                    
                         ═══ Internet (WireGuard tunnel) ═══
                                    
[Switch B] ←─ LDN (802.11) ──→ [Linux PC B]
                                    │
                                    └── (同一構成)
```

### 5.3 L2ブリッジの選択肢
WireGuardはL3（tunデバイス）なので、L2フレームの転送には追加のトンネリングが必要:

| 方式 | 概要 | 備考 |
|------|------|------|
| **GRETAP over WireGuard** | GRETAPトンネルをWireGuardのピアIPを使って構成 | シンプル、低オーバーヘッド |
| **VXLAN over WireGuard** | VXLANでL2オーバーレイ | マルチキャスト対応が楽、将来の拡張性◎ |
| **L2TP/EtherIP over WireGuard** | その他のL2トンネリング | 選択肢として存在 |

---

## 6. 先行事例と参考実装

### 6.1 完全な先行事例: なし
kinnay/LDNをインターネットトンネリングに使用した事例は調査範囲では発見できなかった。本プロジェクトは未踏領域。

### 6.2 参考になる実装

| プロジェクト | 方式 | 参考にすべき点 |
|---|---|---|
| **Ryujinx LDN** (エミュレータ) | エミュレータ内部でLDNサービスをフックし、BSDソケットをアプリケーション層プロキシ経由で転送 | LDNの上位層（BSDソケット）でのプロキシという設計思想。LdnServerリポジトリ: https://github.com/Ryubing/LdnServer |
| **ldn_mitm** (CFW) | Switch内部でLDNサービスをLAN UDPに置換 | LDN→LAN変換のコンセプト。リポジトリ: https://github.com/spacemeowx2/ldn_mitm |
| **switch-lan-play** | LAN通信を中継サーバー経由でトンネリング | LANレベルでのトンネリング手法。ldn_mitmと組み合わせて使用 |
| **XLink Kai** | P2Pトンネリングサービス、モニターモード+パケットインジェクション使用 | OFW Switchのローカル通信にはCFW(ldn_mitm)が必要という結論 |
| **kinnay/NintendoClients** | Switchサーバー通信のリバースエンジニアリング集 | LDN Protocol, Pia Protocol等の仕様書。Wiki: https://github.com/kinnay/NintendoClients/wiki |

### 6.3 GBAtempでの議論（2018年）
- スレッド: https://gbatemp.net/threads/local-wireless-play-over-internet.516675/
- openVPNのTAPモードでブロードキャストパケットを転送すれば原理的に可能という議論
- レイテンシがローカル通信と比較して大きいためゲームが不安定になる懸念の指摘あり

---

## 7. 想定されるリスクと課題

### 7.1 最優先リスク: Wi-Fiドライバ互換性
- A6210 (mt76x2u) がkinnay/LDNで実際に動作するか未検証
- 特にCommon Issues #7（ブロードキャスト宛アクションフレームの破棄）がmt76x2uドライバで発生するかどうか
- **検証方法:** kinnay/LDNのexamplesでスキャン→参加→ホストの順にテスト

### 7.2 レイテンシ
- LDNの認証タイムアウト: 5秒（これ自体は余裕あり）
- アクションフレーム: 100ms間隔（日本国内のWireGuardなら数十msで通過可能）
- ゲームのPia層でのタイムアウト値は不明（ゲームによって異なる可能性）
- **リスク:** ゲームによっては想定外のタイムアウトでセッション切断が起きうる

### 7.3 TAPブリッジの整合性
- kinnay/LDNが作成するTAPインターフェースのフレーム形式がL2ブリッジで正しく中継されるか
- MACアドレスの整合性（LDNはSwitch固有のMACを使うため、ブリッジ経由で書き換えが起きないことの確認）
- ブロードキャストフレームがブリッジの両端で正しく伝搬するか

### 7.4 双方向のホスト/参加の非対称性
- 片方がホスト（AP役）、片方が参加者となる
- ホスト側のLinux PCはAPモード+モニターモードでTAPにフレームを書き込む
- 参加側のLinux PCは参加者としてTAPにフレームを書き込む
- **トンネルの両端で異なる役割を担うため、単純なL2ブリッジだけでは不十分な可能性**
  - 方針A: 片方のLinux PCがLDNに直接参加し、もう片方のLinux PCがAPとしてホストする（TAPフレームをブリッジ）
  - 方針B: 両方のLinux PCがそれぞれのSwitchとLDNで接続し、アプリケーション層でプロキシ（Ryujinx方式に近い）

---

## 8. 推奨開発ステップ

### Phase 1: ローカル検証（インターネット不要）
1. Linux PCにA6210を接続、`mt76x2u`ドライバの確認（`iw list`で対応モード確認）
2. `pip install ldn`
3. `sudo service NetworkManager stop`（有線LAN接続は別途確保）
4. kinnay/LDNのexamplesでSwitchのローカル通信スキャンが見えるか確認
5. LDNネットワークへの参加テスト
6. LDNネットワークのホストテスト（Switch側から参加できるか）
7. TAPインターフェースの動作確認（`ip link`, `tcpdump`でフレーム観測）

### Phase 2: ローカルL2ブリッジ検証（同一LAN内の2台のPCで）
1. 2台のLinux PCにそれぞれA6210を接続
2. 片方がkinnay/LDNでホスト（TAPにフレーム書き込み）
3. もう片方がkinnay/LDNで参加
4. 2台のTAPインターフェースをGRETAP等で直結してL2ブリッジ
5. Switch AがSwitch Bのゲームルームを発見・参加できるか確認

### Phase 3: WireGuard越しの検証
1. 既存WireGuard上にGRETAP or VXLANのL2オーバーレイを構成
2. Phase 2と同様の構成をWireGuard越しで実行
3. レイテンシ測定とゲーム動作確認

### Phase 4: 安定化・自動化
1. 接続スクリプトの作成
2. 再接続ロジック
3. 複数ゲームでの動作検証

---

## 9. 主要リソースリンク集

| リソース | URL |
|---|---|
| kinnay/LDN (コアライブラリ) | https://github.com/kinnay/LDN |
| LDN Pythonパッケージ ドキュメント | https://ldn.readthedocs.io |
| LDNプロトコル仕様 | https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol |
| Local Wireless Communication on PC (ガイド) | https://github.com/kinnay/NintendoClients/wiki/Local-Wireless-Communication-on-PC |
| Piaプロトコル概要 | https://github.com/kinnay/NintendoClients/wiki/Pia-Overview |
| kinnay/LDN Common Issues | https://github.com/kinnay/LDN/wiki/Common-Issues |
| kinnay/LDN Discord | https://discord.gg/x8np6Hhxwk |
| Ryujinx LDN技術ブログ | https://blog.ryujinx.org/local-wireless-technical-walkthrough/ |
| Ryubing/LdnServer | https://github.com/Ryubing/LdnServer |
| ldn_mitm (CFW用、参考) | https://github.com/spacemeowx2/ldn_mitm |
| GBAtemp議論スレッド | https://gbatemp.net/threads/local-wireless-play-over-internet.516675/ |
| mt76ドライバ (カーネル) | https://github.com/openwrt/mt76 |

---

## 10. 補足: 代替アプローチ

もしkinnay/LDN + TAPブリッジのアプローチが技術的に困難な場合の代替案:

1. **アプリケーション層プロキシ（Ryujinx方式）:** kinnay/LDNでLDNネットワークに参加した後のBSDソケット通信をインターセプトし、TCPまたはUDPソケットでインターネット越しに中継。TAPブリッジより制御しやすいが、プロトコル理解が深く必要。

2. **片方のSwitchだけLinux PC経由:** 片方はSwitchを直接LDNで使い、もう片方だけLinux PCがLDN参加者/ホストとして中継する構成。Wi-Fiアダプタが1台で済む。

3. **将来的にSwitch 2への対応:** Switch 2（2025年発売予定）ではLDNプロトコルが変更される可能性があるため、kinnay/NintendoClients wikiの更新を注視。

---

*レポート作成日: 2026-02-20*
*調査に使用したツール: web_search, web_fetch*
