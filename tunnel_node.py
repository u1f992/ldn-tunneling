"""LDN Tunnel Node v4 — MAC スプーフ STA リレー
Usage:
  Primary:   sudo .venv/bin/python tunnel_node.py prod.keys --role primary   --local <wg_ip> --remote <wg_ip> --phy phy1 --switch-b-mac <MAC>
  Secondary: sudo .venv/bin/python tunnel_node.py prod.keys --role secondary --local <wg_ip> --remote <wg_ip> --phy phy1
  Solo test: sudo .venv/bin/python tunnel_node.py prod.keys --role primary   --local <wg_ip> --remote <wg_ip> --phy phy1 --solo

v4 MAC スプーフリレーアーキテクチャ:
  Primary (PC A):   Switch B の MAC で Switch A の AP に STA 接続。
                    Switch A は Switch B が直接参加したと認識する。
                    Pia の AES-GCM nonce (CRC32 に MAC を含む) が一致し、
                    暗号化通信が透過的に成立する。
  Secondary (PC B): ldn.create_network() で Switch A の部屋を複製した AP をホスト。
                    participant 0 を Switch A の情報に書き換え、
                    Switch B から見て Switch A がホストに見える。

  フロー (--switch-b-mac 事前指定により Switch B 参加前に relay 完成):
    1. Primary: scan → NETWORK 情報取得
    2. Primary: tunnel + bridge + STA 接続 (Switch B MAC) + relay 構築
    3. Primary: Secondary 接続待機 → NETWORK + CONNECTED 送信
    4. Secondary: AP 作成 → READY
    5. Switch B が参加 → relay 経由で即座に Pia 通信開始
"""

import argparse
import json
import subprocess
import sys
import types

import trio
import ldn

# --- Constants ---

MK8DX_GAME_ID = 0x0100152000022000
MK8DX_PASSWORD = b"MarioKart8Delux" + b"\x00" * 17

CONTROL_PORT = 39571


# --- Shell helpers ---

def run(cmd):
    print(f"  # {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def run_quiet(cmd):
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# --- Network infrastructure ---

def cleanup_stale_interfaces():
    """前回の異常終了で残った LDN インターフェースを削除する。"""
    # nl80211 仮想インターフェース (iw dev del が確実)
    for ifname in ["ldn", "ldn-mon"]:
        run_quiet(["iw", "dev", ifname, "del"])
    # 通常のインターフェース
    for ifname in ["ldn-tap", "relay-sta", "br-ldn", "gretap1"]:
        run_quiet(["ip", "link", "del", ifname])
    run_quiet(["tc", "qdisc", "del", "dev", "ldn", "ingress"])
    # iptables / policy routing 残骸
    run_quiet(["iptables", "-t", "nat", "-F", "POSTROUTING"])
    run_quiet(["iptables", "-F", "FORWARD"])
    run_quiet(["ip", "rule", "del", "table", "100"])
    run_quiet(["ip", "route", "flush", "table", "100"])


def setup_tunnel(local_ip, remote_ip):
    """GRETAP トンネル + br-ldn ブリッジを構築する。Primary/Secondary 共用。"""
    run(["ip", "link", "add", "gretap1", "type", "gretap",
         "local", local_ip, "remote", remote_ip, "key", "1"])
    run(["ip", "link", "set", "gretap1", "up"])
    run(["ip", "link", "set", "gretap1", "mtu", "1400"])
    run(["ip", "link", "add", "br-ldn", "type", "bridge",
         "stp_state", "0", "forward_delay", "0"])
    run(["ip", "link", "set", "br-ldn", "up"])
    run(["ip", "link", "set", "gretap1", "master", "br-ldn"])
    run(["sysctl", "-w", "net.ipv6.conf.br-ldn.disable_ipv6=1"])


def setup_station_relay(ifname="ldn"):
    """Primary: station IF と bridge 間の L2 リレーを tc mirred redirect で構成する。

    managed-mode WiFi STA は直接 bridge に追加できない (EOPNOTSUPP) ため、
    veth pair + tc ingress redirect で双方向パケットフォワーディングを行う。

    MAC learning を無効化し、全フレームをフラッディングさせる。
    bridge ポートが 2 つ (relay-br + gretap1) のみなので、
    フレームは到着ポート以外の全ポート (= もう 1 つ) に転送される。ループなし。
    """
    # veth pair 作成
    run(["ip", "link", "add", "relay-sta", "type", "veth",
         "peer", "name", "relay-br"])
    run(["ip", "link", "set", "relay-sta", "up"])
    run(["ip", "link", "set", "relay-br", "up"])

    # relay-br を bridge に追加
    run(["ip", "link", "set", "relay-br", "master", "br-ldn"])

    # MAC learning 無効化 — 全フレームをフラッディング
    run(["bridge", "link", "set", "dev", "relay-br", "learning", "off"])
    run(["bridge", "link", "set", "dev", "gretap1", "learning", "off"])

    # tc ingress redirect: station IF → relay-sta
    run(["tc", "qdisc", "add", "dev", ifname, "ingress"])
    run(["tc", "filter", "add", "dev", ifname, "parent", "ffff:",
         "protocol", "all", "u32", "match", "u32", "0", "0",
         "action", "mirred", "egress", "redirect", "dev", "relay-sta"])

    # tc ingress redirect: relay-sta → station IF
    run(["tc", "qdisc", "add", "dev", "relay-sta", "ingress"])
    run(["tc", "filter", "add", "dev", "relay-sta", "parent", "ffff:",
         "protocol", "all", "u32", "match", "u32", "0", "0",
         "action", "mirred", "egress", "redirect", "dev", ifname])

    # IPv6 無効化
    run(["sysctl", "-w", "net.ipv6.conf.relay-sta.disable_ipv6=1"])
    run(["sysctl", "-w", "net.ipv6.conf.relay-br.disable_ipv6=1"])


def teardown_tunnel():
    """トンネルとリレーを削除する。Primary/Secondary 共用。"""
    print("Cleaning up...")
    run_quiet(["tc", "qdisc", "del", "dev", "ldn", "ingress"])
    run_quiet(["ip", "link", "del", "relay-sta"])   # veth peer も自動削除
    run_quiet(["ip", "link", "del", "br-ldn"])
    run_quiet(["ip", "link", "del", "gretap1"])


def add_tap_to_bridge():
    """Secondary: TAP を br-ldn に追加する。MAC learning 無効化でフラッディング強制。"""
    run(["ip", "link", "set", "ldn-tap", "master", "br-ldn"])
    run(["bridge", "link", "set", "dev", "ldn-tap", "learning", "off"])
    run(["bridge", "link", "set", "dev", "gretap1", "learning", "off"])
    run(["sysctl", "-w", "net.ipv6.conf.ldn-tap.disable_ipv6=1"])


# --- Monkey-patching (Secondary only) ---

def patch_secondary_network(network, net_msg):
    """Secondary の APNetwork を Switch A のプロキシとしてパッチする。

    1. _network_id を Switch A のサブネット ID に統一
    2. participant 0 を Switch A の情報に書き換え
    3. TAP IP を .254 に設定 — Switch A の IP (.1) を横取りしない
    4. _register_participant を index 1+ に制限 — index 0=Switch A
    """
    network_id = net_msg["network_id"]
    host = net_msg["participants"][0]

    # 1. _network_id 統一
    network._network_id = network_id

    # 2. participant 0 = Switch A
    p0 = network._network.participants[0]
    p0.ip_address = host["ip"]
    p0.mac_address = ldn.MACAddress(host["mac"])
    p0.name = bytes.fromhex(host["name"])
    p0.app_version = host["app_version"]
    p0.platform = host["platform"]

    # 3. TAP IP を .254 に設定
    subprocess.run(["ip", "addr", "flush", "dev", "ldn-tap"], check=True)
    subprocess.run(["ip", "addr", "add",
                    f"169.254.{network_id}.254/24",
                    "brd", f"169.254.{network_id}.255",
                    "dev", "ldn-tap"], check=True)

    # 4. _register_participant パッチ (index 0=Switch A 予約, 1-7=Switch B+)
    async def patched_register(self, address, name, app_version, platform):
        target_index = None
        for idx in range(1, 8):
            if not self._network.participants[idx].connected:
                target_index = idx
                break

        if target_index is None:
            print("  [WARN] No free participant slot (index 1-7)")
            return

        self._peers.append(address)

        participant = ldn.ParticipantInfo()
        participant.ip_address = f"169.254.{self._network_id}.{target_index + 1}"
        participant.mac_address = address
        participant.connected = True
        participant.name = name
        participant.app_version = app_version
        participant.platform = platform

        self._network.participants[target_index] = participant
        self._network.num_participants += 1
        self._update_nonce()

        await self._interface.add_neighbor(
            participant.ip_address, participant.mac_address
        )
        await self._events.put(ldn.JoinEvent(target_index, participant))

    network._register_participant = types.MethodType(patched_register, network)

    # アドバタイズメント更新
    network._update_nonce()


def inject_virtual_participant(network, index, ip, mac_str, name, app_version, platform):
    """対向拠点の参加者を仮想参加者としてアドバタイズメントに注入する。"""
    participant = ldn.ParticipantInfo()
    participant.ip_address = ip
    participant.mac_address = ldn.MACAddress(mac_str)
    participant.connected = True
    participant.name = name
    participant.app_version = app_version
    participant.platform = platform

    network._network.participants[index] = participant
    network._network.num_participants += 1
    network._update_nonce()


def remove_virtual_participant(network, index):
    """仮想参加者をアドバタイズメントから除去する。"""
    participant = network._network.participants[index]
    if participant.connected:
        participant.connected = False
        network._network.num_participants -= 1
        network._update_nonce()


# --- Control channel ---

class LineReader:
    """trio.SocketStream をラップして行単位の読み取りを提供する。"""

    def __init__(self, stream):
        self.stream = stream
        self._buf = b""

    async def readline(self):
        while b"\n" not in self._buf:
            data = await self.stream.receive_some(4096)
            if not data:
                raise trio.EndOfChannel("Connection closed")
            self._buf += data
        line, self._buf = self._buf.split(b"\n", 1)
        return line


async def send_msg(stream, msg):
    data = json.dumps(msg).encode() + b"\n"
    await stream.send_all(data)


async def recv_msg(reader):
    line = await reader.readline()
    return json.loads(line)


# --- Message builders ---

def make_network_msg_from_scan(info):
    """scan 結果の NetworkInfo を NETWORK メッセージに変換する。

    scan() が返す NetworkInfo は advertisement frame を解析した結果であり、
    STA 接続せずに全情報を取得できる。
    """
    # network_id: host の IP (169.254.X.1) から X を抽出
    host_ip = info.participants[0].ip_address
    network_id = int(host_ip.split(".")[2])

    participants = []
    for i, p in enumerate(info.participants):
        participants.append({
            "index": i,
            "ip": p.ip_address,
            "mac": str(p.mac_address),
            "connected": p.connected,
            "name": p.name.hex() if p.name else "",
            "app_version": p.app_version,
            "platform": p.platform,
        })
    # 8 エントリに満たない場合はパディング
    for i in range(len(info.participants), 8):
        participants.append({
            "index": i,
            "ip": "",
            "mac": "00:00:00:00:00:00",
            "connected": False,
            "name": "",
            "app_version": 0,
            "platform": 0,
        })

    return {
        "type": "network",
        "network_id": network_id,
        "local_communication_id": info.local_communication_id,
        "scene_id": info.scene_id,
        "channel": info.channel,
        "protocol": info.protocol,
        "version": info.version,
        "app_version": info.app_version,
        "max_participants": info.max_participants,
        "security_mode": info.security_mode,
        "accept_policy": info.accept_policy,
        "application_data": info.application_data.hex(),
        "server_random": info.server_random.hex(),
        "ssid": info.ssid.hex(),
        "participants": participants,
    }


def pick_secondary_channel(primary_channel):
    """Secondary AP を Primary とは別のチャネルで運用する。

    同一チャネルだと Switch A が spoofed STA と実 Switch B の MAC 衝突を検知し
    disassociate する。2.4 GHz 非重複チャネル (1, 6, 11) から選択。
    """
    non_overlapping = [1, 6, 11]
    candidates = [ch for ch in non_overlapping if ch != primary_channel]
    return candidates[0]


def make_create_param(keys, phy, msg):
    """NETWORK メッセージから CreateNetworkParam を構築する。"""
    param = ldn.CreateNetworkParam()
    param.keys = keys
    param.phyname = phy
    param.phyname_monitor = phy
    param.local_communication_id = msg["local_communication_id"]
    param.scene_id = msg["scene_id"]
    param.channel = pick_secondary_channel(msg["channel"])
    param.protocol = msg["protocol"]
    param.version = msg["version"]
    param.app_version = msg["app_version"]
    param.max_participants = msg["max_participants"]
    param.security_mode = msg["security_mode"]
    param.accept_policy = msg["accept_policy"]
    param.application_data = bytes.fromhex(msg["application_data"])
    param.server_random = bytes.fromhex(msg["server_random"])
    param.ssid = bytes.fromhex(msg["ssid"])
    param.password = MK8DX_PASSWORD
    param.name = b"LDN-Tunnel"
    return param


def make_join_msg(index, participant):
    return {
        "type": "join",
        "index": index,
        "ip": participant.ip_address,
        "mac": str(participant.mac_address),
        "name": participant.name.hex(),
        "app_version": participant.app_version,
        "platform": participant.platform,
    }


def make_leave_msg(index):
    return {"type": "leave", "index": index}


# --- LDN scan ---

async def scan_mk8dx(keys, phy):
    for attempt in range(10):
        print(f"Scan {attempt + 1}/10...", end=" ", flush=True)
        networks = await ldn.scan(
            keys=keys, phyname=phy, ifname="ldn",
            channels=[1, 6, 11], dwell_time=0.130, protocols=[1, 3],
        )
        print(f"{len(networks)} found")
        for net in networks:
            if net.local_communication_id == MK8DX_GAME_ID:
                return net
    return None


# --- Event handling ---

async def handle_primary_events(sta, peer_stream, relay_mac):
    """Primary: STANetwork のイベントを監視し、制御チャネルで Secondary に転送する。

    relay_mac: 自身の STA MAC (= Switch B の MAC)。
    自分自身の JoinEvent はフィルタして Secondary に転送しない。
    """
    try:
        while True:
            event = await sta.next_event()
            if isinstance(event, ldn.JoinEvent):
                p = event.participant
                # 自身の参加イベントはスキップ
                if str(p.mac_address) == relay_mac:
                    print(f"  [PRIMARY JOIN] idx={event.index}"
                          f" (self, skipping relay)")
                    continue
                print(f"  [PRIMARY JOIN] idx={event.index}"
                      f" {p.name.decode(errors='replace')}"
                      f" IP={p.ip_address} MAC={p.mac_address}")
                await send_msg(peer_stream, make_join_msg(event.index, p))
            elif isinstance(event, ldn.LeaveEvent):
                p = event.participant
                print(f"  [PRIMARY LEAVE] idx={event.index}"
                      f" {p.name.decode(errors='replace')}")
                await send_msg(peer_stream, make_leave_msg(event.index))
            elif isinstance(event, ldn.ApplicationDataChanged):
                print(f"  [APP_DATA] {len(event.new)} bytes")
                await send_msg(peer_stream, {
                    "type": "app_data",
                    "data": event.new.hex(),
                })
            elif isinstance(event, ldn.AcceptPolicyChanged):
                print(f"  [ACCEPT] {event.old} -> {event.new}")
                await send_msg(peer_stream, {
                    "type": "accept",
                    "policy": event.new,
                })
            elif isinstance(event, ldn.DisconnectEvent):
                print(f"  [DISCONNECT] reason={event.reason}")
                break
    except (trio.ClosedResourceError, trio.BrokenResourceError):
        pass


async def handle_secondary_events(network, peer_stream):
    """Secondary: APNetwork のローカルイベントを監視し、Primary に転送する。

    Switch B が参加/離脱した際に Primary へ通知する。
    """
    while True:
        event = await network.next_event()
        if isinstance(event, ldn.JoinEvent):
            p = event.participant
            print(f"  [SECONDARY JOIN] idx={event.index}"
                  f" {p.name.decode(errors='replace')}"
                  f" IP={p.ip_address} MAC={p.mac_address}")
            await send_msg(peer_stream, make_join_msg(event.index, p))
        elif isinstance(event, ldn.LeaveEvent):
            p = event.participant
            print(f"  [SECONDARY LEAVE] idx={event.index}"
                  f" {p.name.decode(errors='replace')}")
            await send_msg(peer_stream, make_leave_msg(event.index))


async def handle_peer_messages_primary(reader):
    """Primary: Secondary からのメッセージを処理する。

    LEAVE はログに記録するのみ (自動終了しない)。
    TCP 切断時のみ return → nursery cancel。
    """
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            print("  [CTRL] Secondary disconnected")
            break

        if msg["type"] == "leave":
            print(f"  [REMOTE LEAVE] idx={msg['index']}"
                  f" (continuing relay)")
        elif msg["type"] == "join":
            # 追加の参加者 (将来対応)
            print(f"  [REMOTE JOIN] idx={msg['index']}"
                  f" IP={msg['ip']} MAC={msg['mac']}"
                  f" (additional participant, not yet supported)")


async def handle_peer_messages_secondary(network, reader):
    """Secondary: Primary からの JOIN/LEAVE/APP_DATA/ACCEPT を処理する。"""
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            print("  [CTRL] Primary disconnected")
            break

        if msg["type"] == "join":
            print(f"  [REMOTE JOIN] idx={msg['index']}"
                  f" IP={msg['ip']} MAC={msg['mac']}")
            inject_virtual_participant(
                network,
                index=msg["index"],
                ip=msg["ip"],
                mac_str=msg["mac"],
                name=bytes.fromhex(msg["name"]),
                app_version=msg["app_version"],
                platform=msg["platform"],
            )
        elif msg["type"] == "leave":
            print(f"  [REMOTE LEAVE] idx={msg['index']}")
            remove_virtual_participant(network, msg["index"])
        elif msg["type"] == "app_data":
            print(f"  [APP_DATA] updating ({len(msg['data']) // 2} bytes)")
            network.set_application_data(bytes.fromhex(msg["data"]))
        elif msg["type"] == "accept":
            print(f"  [ACCEPT] policy={msg['policy']}")
            network.set_accept_policy(msg["policy"])
        elif msg["type"] == "connected":
            primary_idx = msg["index"]
            primary_ip = msg["ip"]
            print(f"  [CONNECTED] Primary STA assigned: idx={primary_idx}"
                  f" IP={primary_ip}")
            # Switch B の IP と一致するか確認
            for idx, p in enumerate(network._network.participants):
                if p.connected and idx > 0:
                    if p.ip_address != primary_ip:
                        print(f"  [WARN] IP mismatch! Switch B has"
                              f" {p.ip_address}, Primary expects"
                              f" {primary_ip}")
                    else:
                        print(f"  [OK] IP match: {p.ip_address}")
        elif msg["type"] == "accept":
            print(f"  [ACCEPT] policy={msg['policy']}")
            network.set_accept_policy(msg["policy"])


# --- Main flows ---

async def run_primary(args):
    keys = ldn.load_keys(args.keys)
    cleanup_stale_interfaces()

    # 1. Scan (STA 接続はしない — scan 結果から全情報を取得)
    print("=== 1. Scan for MK8DX ===")
    print("Switch A でローカル通信の部屋を作ってください")
    print()
    info = await scan_mk8dx(keys, args.phy)
    if info is None:
        print("MK8DX network not found.")
        return

    host = info.participants[0]
    host_ip = host.ip_address
    network_id = int(host_ip.split(".")[2])
    print(f"\n  ch={info.channel} proto={info.protocol} ver={info.version}"
          f" app_ver={info.app_version}")
    print(f"  BSSID={info.address}")
    print(f"  Host: IP={host_ip} MAC={host.mac_address}")
    print(f"  network_id={network_id}")
    print()

    if args.solo:
        # Solo mode: 従来通り PC A の MAC で接続して監視
        print("=== 2. Solo: Connecting as STA ===")
        param = ldn.ConnectNetworkParam()
        param.keys = keys
        param.phyname = args.phy
        param.network = info
        param.password = MK8DX_PASSWORD
        param.name = b"LDN-Tunnel"

        async with ldn.connect(param) as sta:
            print(f"  Connected (participant {sta._participant_id})")
            print(f"  IP: {sta.participant().ip_address}")
            print("Ctrl+C で終了")
            print()
            while True:
                event = await sta.next_event()
                if isinstance(event, ldn.JoinEvent):
                    p = event.participant
                    print(f"  [JOIN] idx={event.index}"
                          f" {p.name.decode(errors='replace')}"
                          f" IP={p.ip_address} MAC={p.mac_address}")
                elif isinstance(event, ldn.LeaveEvent):
                    p = event.participant
                    print(f"  [LEAVE] idx={event.index}"
                          f" {p.name.decode(errors='replace')}")
                elif isinstance(event, ldn.ApplicationDataChanged):
                    print(f"  [APP_DATA] {len(event.new)} bytes")
                elif isinstance(event, ldn.AcceptPolicyChanged):
                    print(f"  [ACCEPT] {event.old} -> {event.new}")
                elif isinstance(event, ldn.DisconnectEvent):
                    print(f"  [DISCONNECT] reason={event.reason}")
                    break
        return

    # --- Non-solo mode: Switch B の MAC で先に STA 接続 + relay 構築 ---
    # Switch B 参加前に relay を完成させることで Pia タイムアウトを回避する

    switch_b_mac = args.switch_b_mac
    if switch_b_mac is None:
        print("Error: --switch-b-mac is required for non-solo mode")
        print("Switch B の MAC は「設定 → インターネット」で確認できます")
        return

    # 2. GRETAP tunnel + bridge
    print("=== 2. GRETAP tunnel + bridge ===")
    setup_tunnel(args.local, args.remote)
    print()

    try:
        # 3. STA 接続 (Switch B 参加前に relay を完成させる)
        print(f"=== 3. Connecting to Switch A as {switch_b_mac} ===")
        param = ldn.ConnectNetworkParam()
        param.keys = keys
        param.phyname = args.phy
        param.network = info
        param.password = MK8DX_PASSWORD
        param.name = b"LDN-Tunnel"
        param.address = ldn.MACAddress(switch_b_mac)

        max_connect_attempts = 3
        for attempt in range(max_connect_attempts):
            if attempt > 0:
                print(f"\n  Retry {attempt + 1}/{max_connect_attempts}"
                      f" in 2 seconds...")
                await trio.sleep(2)
                # Re-scan for fresh NetworkInfo
                print("  Re-scanning...")
                fresh_info = await scan_mk8dx(keys, args.phy)
                if fresh_info is None:
                    print("  Network not found!")
                    continue
                param.network = fresh_info

            try:
                async with ldn.connect(param) as sta:
                    sta_index = sta._participant_id
                    sta_ip = sta.participant().ip_address
                    print(f"  Connected (participant {sta_index})")
                    print(f"  IP: {sta_ip}")
                    print(f"  MAC: {switch_b_mac} (spoofed)")
                    print()

                    # 4. Relay 構築 (Switch B 参加前に完成)
                    print("=== 4. Setting up relay ===")
                    setup_station_relay()
                    print()

                    # 5. Secondary 待機
                    listeners = await trio.open_tcp_listeners(
                        CONTROL_PORT, host=args.local)
                    try:
                        print(f"=== 5. Waiting for secondary"
                              f" on port {CONTROL_PORT} ===")
                        print(f"  Listening on"
                              f" {args.local}:{CONTROL_PORT}")

                        peer_stream = await listeners[0].accept()
                        reader = LineReader(peer_stream)
                        print("  Secondary connected!")

                        # 6. NETWORK + CONNECTED 送信
                        net_msg = make_network_msg_from_scan(info)
                        await send_msg(peer_stream, net_msg)
                        await send_msg(peer_stream, {
                            "type": "connected",
                            "index": sta_index,
                            "ip": sta_ip,
                        })
                        print("  NETWORK + CONNECTED sent,"
                              " waiting for READY...")

                        try:
                            ready_msg = await recv_msg(reader)
                        except (trio.ClosedResourceError,
                                trio.EndOfChannel):
                            print("  Secondary disconnected"
                                  " before READY")
                            return
                        assert ready_msg["type"] == "ready", \
                            f"Expected 'ready', got {ready_msg}"
                        print("  Secondary is ready!")
                        print()

                        print("=== Ready ===")
                        print("Switch B で「ローカル通信」"
                              "から参加してください")
                        print("Pia 通信が透過的にリレーされます")
                        print("Ctrl+C で終了")
                        print()

                        # 7. Event loop
                        async with trio.open_nursery() as nursery:
                            nursery.start_soon(
                                handle_primary_events,
                                sta, peer_stream, switch_b_mac)

                            async def _wait_secondary(
                                reader=reader,
                            ):
                                await handle_peer_messages_primary(
                                    reader)
                                nursery.cancel_scope.cancel()

                            nursery.start_soon(_wait_secondary)

                    finally:
                        for listener in listeners:
                            await listener.aclose()

                    # Event loop 正常終了 → retry 不要
                    break
            except ConnectionError as e:
                print(f"  Connect failed: {e}")
                if attempt < max_connect_attempts - 1:
                    print("  Will retry...")
                    continue
                raise

    finally:
        teardown_tunnel()


async def run_secondary(args):
    keys = ldn.load_keys(args.keys)
    cleanup_stale_interfaces()

    # 1. GRETAP + bridge
    print("=== 1. GRETAP tunnel + bridge ===")
    setup_tunnel(args.local, args.remote)
    print()

    try:
        # 2. Connect to primary
        print(f"=== 2. Connecting to primary at {args.remote}:{CONTROL_PORT} ===")
        peer_stream = await trio.open_tcp_stream(args.remote, CONTROL_PORT)
        reader = LineReader(peer_stream)
        print("  Connected!")

        # 3. Receive NETWORK
        net_msg = await recv_msg(reader)
        assert net_msg["type"] == "network", \
            f"Expected 'network', got {net_msg}"
        network_id = net_msg["network_id"]
        host_p = net_msg["participants"][0]
        print(f"  Received NETWORK:"
              f" game_id={net_msg['local_communication_id']:#018x}"
              f" ch={net_msg['channel']} network_id={network_id}")
        print(f"  Host (Switch A): IP={host_p['ip']} MAC={host_p['mac']}")
        print()

        # 4. Host proxy LDN
        print("=== 3. Hosting proxy LDN network ===")
        param = make_create_param(keys, args.phy, net_msg)

        async with ldn.create_network(param) as network:
            # 5. Patch: Switch A のプロキシとして構成
            patch_secondary_network(network, net_msg)

            # 6. Bridge TAP
            add_tap_to_bridge()

            # 7. Signal ready
            await send_msg(peer_stream, {"type": "ready"})

            print(f"  subnet: 169.254.{network_id}.0/24")
            print(f"  participant 0 (Switch A):"
                  f" {host_p['ip']} {host_p['mac']}")
            print()
            print("=== Ready ===")
            print("Switch B で「ローカル通信」から参加してください")
            print("Ctrl+C で終了")
            print()

            async with trio.open_nursery() as nursery:
                nursery.start_soon(
                    handle_secondary_events, network, peer_stream)
                nursery.start_soon(
                    handle_peer_messages_secondary, network, reader)

    finally:
        teardown_tunnel()


async def main():
    parser = argparse.ArgumentParser(description="LDN Tunnel Node v4")
    parser.add_argument("keys", help="prod.keys のパス")
    parser.add_argument("--role", required=True,
                        choices=["primary", "secondary"],
                        help="primary: MAC スプーフ STA リレー、secondary: AP プロキシ")
    parser.add_argument("--local", required=True,
                        help="ローカル WireGuard IP")
    parser.add_argument("--remote", required=True,
                        help="リモート WireGuard IP")
    parser.add_argument("--phy", required=True,
                        help="Wi-Fi phy 名 (例: phy1)")
    parser.add_argument("--switch-b-mac", default=None,
                        help="Switch B の MAC アドレス (例: 64:B5:C6:1B:14:9B)")
    parser.add_argument("--solo", action="store_true",
                        help="単拠点テスト: STA 参加のみ (トンネルなし)")
    args = parser.parse_args()

    if args.role == "primary":
        await run_primary(args)
    else:
        await run_secondary(args)


trio.run(main)
