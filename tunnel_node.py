"""LDN Tunnel Node v3 — Phase 2 (非対称 STA + AP)
Usage:
  Primary:   sudo .venv/bin/python tunnel_node.py prod.keys --role primary   --local <wg_ip> --remote <wg_ip> --phy phy1
  Secondary: sudo .venv/bin/python tunnel_node.py prod.keys --role secondary --local <wg_ip> --remote <wg_ip> --phy phy1
  Solo test: sudo .venv/bin/python tunnel_node.py prod.keys --role primary   --local <wg_ip> --remote <wg_ip> --phy phy1 --solo

v3 非対称アーキテクチャ:
  Primary (PC A):   ldn.connect() で Switch A の LDN 部屋に STA として参加。
                    station IF を Linux bridge 経由で GRETAP トンネルに接続。
  Secondary (PC B): ldn.create_network() で Switch A の部屋を複製した AP をホスト。
                    participant 0 を Switch A の情報に書き換え、
                    Switch B から見て Switch A がホストに見える。
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
    for ifname in ["ldn", "ldn-mon", "ldn-tap", "relay-sta", "br-ldn", "gretap1"]:
        run_quiet(["ip", "link", "del", ifname])
    run_quiet(["tc", "qdisc", "del", "dev", "ldn", "ingress"])


def setup_tunnel(local_ip, remote_ip):
    run(["ip", "link", "add", "gretap1", "type", "gretap",
         "local", local_ip, "remote", remote_ip, "key", "1"])
    run(["ip", "link", "set", "gretap1", "up"])
    run(["ip", "link", "add", "br-ldn", "type", "bridge",
         "stp_state", "0", "forward_delay", "0"])
    run(["ip", "link", "set", "br-ldn", "up"])
    run(["ip", "link", "set", "gretap1", "master", "br-ldn"])
    run(["sysctl", "-w", "net.ipv6.conf.br-ldn.disable_ipv6=1"])


def teardown_tunnel():
    print("Cleaning up...")
    run_quiet(["tc", "qdisc", "del", "dev", "ldn", "ingress"])
    run_quiet(["ip", "link", "del", "relay-sta"])   # veth peer も自動削除
    run_quiet(["ip", "link", "del", "br-ldn"])
    run_quiet(["ip", "link", "del", "gretap1"])


def setup_station_relay(ifname="ldn"):
    """Primary: station IF と bridge 間の L2 リレーを tc mirred redirect で構成する。

    managed-mode WiFi STA は直接 bridge に追加できない (EOPNOTSUPP) ため、
    veth pair + tc ingress redirect で双方向パケットフォワーディングを行う。

    パケット経路:
      受信: Switch A → [station IF] →(tc)→ [relay-sta] →(veth)→ [relay-br] → bridge
      送信: bridge → [relay-br] →(veth)→ [relay-sta] →(tc)→ [station IF] → Switch A
    """
    # veth pair 作成
    run(["ip", "link", "add", "relay-sta", "type", "veth",
         "peer", "name", "relay-br"])
    run(["ip", "link", "set", "relay-sta", "up"])
    run(["ip", "link", "set", "relay-br", "up"])

    # relay-br を bridge に追加
    run(["ip", "link", "set", "relay-br", "master", "br-ldn"])

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


def add_tap_to_bridge():
    """Secondary: TAP を br-ldn に追加する。"""
    run(["ip", "link", "set", "ldn-tap", "master", "br-ldn"])
    run(["sysctl", "-w", "net.ipv6.conf.ldn-tap.disable_ipv6=1"])


# --- Monkey-patching (Secondary only) ---

def patch_secondary_network(network, net_msg):
    """Secondary の APNetwork を Switch A のプロキシとしてパッチする。

    1. _network_id を Switch A のサブネット ID に統一 (__init__.py:1512)
    2. participant 0 を Switch A の情報に書き換え (__init__.py:1514-1521)
    3. TAP IP を再設定 (__init__.py:1781 で設定済みのランダム値を修正)
    4. _register_participant を index 1+ に制限 (__init__.py:1732-1734)
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

    # 3. TAP IP 再設定 (_initialize_network でランダム値が設定済み)
    subprocess.run(["ip", "addr", "flush", "dev", "ldn-tap"], check=True)
    subprocess.run(["ip", "addr", "add",
                    f"169.254.{network_id}.1/24",
                    "brd", f"169.254.{network_id}.255",
                    "dev", "ldn-tap"], check=True)

    # 4. _register_participant パッチ (index 0 は Switch A 用に予約)
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
    """対向拠点の参加者を仮想参加者としてアドバタイズメントに注入する。

    APNetwork._network.participants[index] に直接書き込み、
    _update_nonce() でアドバタイズメント更新をトリガーする (__init__.py:1675)。
    """
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

def make_network_msg(sta):
    """STANetwork の全状態を NETWORK メッセージに変換する。

    Primary → Secondary: Switch A の部屋の全情報を送信。
    Secondary はこれを基に APNetwork を構築し、Switch A の部屋を複製する。
    """
    net = sta._network
    participants = []
    for i in range(8):
        p = net.participants[i]
        participants.append({
            "index": i,
            "ip": p.ip_address,
            "mac": str(p.mac_address),
            "connected": p.connected,
            "name": p.name.hex() if p.name else "",
            "app_version": p.app_version,
            "platform": p.platform,
        })

    return {
        "type": "network",
        "network_id": sta._network_id,
        "local_communication_id": net.local_communication_id,
        "scene_id": net.scene_id,
        "channel": net.channel,
        "protocol": net.protocol,
        "version": net.version,
        "app_version": net.app_version,
        "max_participants": net.max_participants,
        "security_mode": net.security_mode,
        "accept_policy": net.accept_policy,
        "application_data": net.application_data.hex(),
        "server_random": net.server_random.hex(),
        "ssid": net.ssid.hex(),
        "participants": participants,
    }


def make_create_param(keys, phy, msg):
    """NETWORK メッセージから CreateNetworkParam を構築する。"""
    param = ldn.CreateNetworkParam()
    param.keys = keys
    param.phyname = phy
    param.phyname_monitor = phy
    param.local_communication_id = msg["local_communication_id"]
    param.scene_id = msg["scene_id"]
    param.channel = msg["channel"]
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

async def handle_primary_events(sta, peer_stream):
    """Primary: STANetwork のイベントを監視し、制御チャネルで Secondary に転送する。

    STANetwork._monitor_network (__init__.py:1421-1462) が生成するイベント:
    - JoinEvent/LeaveEvent: Switch A の部屋の参加者変更
    - ApplicationDataChanged: ゲーム状態の更新 (ロビー、コース選択等)
    - AcceptPolicyChanged: 参加受付ポリシーの変更
    - DisconnectEvent: Switch A との接続断
    """
    while True:
        event = await sta.next_event()
        if isinstance(event, ldn.JoinEvent):
            p = event.participant
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


async def handle_peer_messages_primary(sta, reader):
    """Primary: Secondary からの JOIN/LEAVE を受信してログに記録する。

    STANetwork はアドバタイズメントを制御できないため、
    仮想参加者の注入はできない。ログ記録のみ。
    """
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            print("  [CTRL] Secondary disconnected")
            break

        if msg["type"] == "join":
            print(f"  [REMOTE JOIN] idx={msg['index']}"
                  f" IP={msg['ip']} MAC={msg['mac']}")
        elif msg["type"] == "leave":
            print(f"  [REMOTE LEAVE] idx={msg['index']}")


async def handle_peer_messages_secondary(network, reader):
    """Secondary: Primary からの JOIN/LEAVE/APP_DATA/ACCEPT を処理する。

    - JOIN/LEAVE: Switch A 側の参加者変更 → 仮想参加者として注入/除去
    - APP_DATA: ゲーム状態の更新 → APNetwork に反映
    - ACCEPT: 参加受付ポリシーの変更 → APNetwork に反映
    """
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


# --- Main flows ---

async def run_primary(args):
    keys = ldn.load_keys(args.keys)
    cleanup_stale_interfaces()

    # 1. Scan
    print("=== 1. Scan for MK8DX ===")
    print("Switch A でローカル通信の部屋を作ってください")
    print()
    info = await scan_mk8dx(keys, args.phy)
    if info is None:
        print("MK8DX network not found.")
        return

    print(f"\n  ch={info.channel} proto={info.protocol} ver={info.version}"
          f" app_ver={info.app_version}")
    print(f"  BSSID={info.address}")
    print()

    # 2. Connect as STA
    print("=== 2. Connecting to Switch A's LDN network ===")
    param = ldn.ConnectNetworkParam()
    param.keys = keys
    param.phyname = args.phy
    param.network = info
    param.password = MK8DX_PASSWORD
    param.name = b"LDN-Tunnel"

    async with ldn.connect(param) as sta:
        net = sta._network
        print(f"  Connected as STA (participant {sta._participant_id})")
        print(f"  network_id: {sta._network_id}")
        print(f"  IP: {sta.participant().ip_address}")
        print(f"  Host (Switch A): IP={net.participants[0].ip_address}"
              f" MAC={net.participants[0].mac_address}")
        print()

        if args.solo:
            # Solo mode: STA 参加の確認のみ
            print("=== Solo mode: monitoring events ===")
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
        else:
            # Full mode: tunnel + control channel
            print("=== 3. GRETAP tunnel + bridge ===")
            setup_tunnel(args.local, args.remote)
            try:
                setup_station_relay()
                print()

                # Wait for secondary
                print(f"=== 4. Waiting for secondary on port {CONTROL_PORT} ===")
                listeners = await trio.open_tcp_listeners(
                    CONTROL_PORT, host=args.local)
                print(f"  Listening on {args.local}:{CONTROL_PORT}")

                peer_stream = await listeners[0].accept()
                for listener in listeners:
                    await listener.aclose()
                reader = LineReader(peer_stream)
                print("  Secondary connected!")

                # Send NETWORK message
                net_msg = make_network_msg(sta)
                await send_msg(peer_stream, net_msg)
                print("  NETWORK sent, waiting for READY...")

                ready_msg = await recv_msg(reader)
                assert ready_msg["type"] == "ready", \
                    f"Expected 'ready', got {ready_msg}"
                print("  Secondary is ready!")
                print()

                print("=== Ready ===")
                print("Switch B で「ローカル通信」から参加してください")
                print("Ctrl+C で終了")
                print()

                async with trio.open_nursery() as nursery:
                    nursery.start_soon(
                        handle_primary_events, sta, peer_stream)
                    nursery.start_soon(
                        handle_peer_messages_primary, sta, reader)

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
    parser = argparse.ArgumentParser(description="LDN Tunnel Node v3")
    parser.add_argument("keys", help="prod.keys のパス")
    parser.add_argument("--role", required=True,
                        choices=["primary", "secondary"],
                        help="primary: STA 参加+中継、secondary: AP プロキシ")
    parser.add_argument("--local", required=True,
                        help="ローカル WireGuard IP")
    parser.add_argument("--remote", required=True,
                        help="リモート WireGuard IP")
    parser.add_argument("--phy", required=True,
                        help="Wi-Fi phy 名 (例: phy1)")
    parser.add_argument("--solo", action="store_true",
                        help="単拠点テスト: STA 参加のみ (トンネルなし)")
    args = parser.parse_args()

    if args.role == "primary":
        await run_primary(args)
    else:
        await run_secondary(args)


trio.run(main)
