# LDN Tunneling — 作業ノート

## 環境情報
- **OS:** Ubuntu 24.04.4 LTS
- **Kernel:** 6.17.0-14-generic
- **Python:** 3.12.3 (uv管理)
- **ldn:** 0.0.16 (uv add済み)
- **mt76x2uドライバ:** カーネルモジュール利用可能 (`/lib/modules/6.17.0-14-generic/...`)
- **既存NIC:** wlp3s0 (内蔵Wi-Fi, DOWN状態), wg0 (WireGuard, UP)

## Phase 1: ローカル検証

### Step 1: A6210接続・ドライバ確認
- [ ] A6210をUSBに接続
- [ ] `lsusb`でデバイス認識確認 (Vendor: 0846, Product: 9053 が典型)
- [ ] `dmesg`でmt76x2uドライバ自動ロード確認
- [ ] `iw list`で対応モード確認 (AP, monitor, managed が必要)
- [ ] `iw dev`で新しいインターフェース名確認

### Step 2: LDNスキャンテスト
- [ ] NetworkManager停止 (Wi-Fiアダプタへの干渉防止)
- [ ] kinnay/LDNのスキャン例でSwitch検出テスト

### Step 3: LDNネットワーク参加テスト
### Step 4: LDNネットワークホストテスト
### Step 5: TAPインターフェース確認

---

## ログ

### 2026-02-20: 初期セットアップ
- uv init + uv add ldn 完了
- mt76x2uモジュールはカーネルに含まれている（未ロード、A6210未接続のため）
- A6210はまだ物理的に未接続
