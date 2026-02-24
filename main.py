"""LDN Tunnel Node v4 — MAC スプーフ STA リレー
Usage:
  Primary:   sudo .venv/bin/python main.py prod.keys --role primary   --local <wg_ip> --remote <wg_ip> --phy phy1 --switch-b-mac <MAC> --ldn-passphrase <FILE>
  Secondary: sudo .venv/bin/python main.py prod.keys --role secondary --local <wg_ip> --remote <wg_ip> --phy phy1 --ldn-passphrase <FILE>

一部のゲームの LDN パスフレーズは以下で公開されている:
  https://github.com/kinnay/NintendoClients/wiki/LDN-Passphrases

MK8DX の場合:
  printf 'MarioKart8Delux\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > mk8dx.pass
  sudo .venv/bin/python main.py prod.keys --role primary --local 10.0.0.1 --remote 10.0.0.2 --phy phy1 --switch-b-mac 64:B5:C6:1B:14:9B --ldn-passphrase mk8dx.pass

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
import types
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator

import trio
import ldn
from pyroute2 import IPRoute, protocols
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.rtnl import TC_H_ROOT


# --- Constants ---

DEFAULT_CONTROL_PORT = 39571

IF_LDN = "ldn"
IF_LDN_MON = "ldn-mon"
IF_LDN_TAP = "ldn-tap"
IF_RELAY_STA = "relay-sta"
IF_RELAY_BR = "relay-br"
IF_BRIDGE = "br-ldn"
IF_GRETAP = "gretap1"


# --- Config ---


@dataclass(frozen=True)
class _BaseConfig:
    keys: str
    phy: str
    ldn_passphrase: bytes | None
    local: str
    remote: str
    control_port: int

    def __post_init__(self):
        for field, expected in {
            "keys": str,
            "phy": str,
            "ldn_passphrase": (bytes, type(None)),
            "local": str,
            "remote": str,
            "control_port": int,
        }.items():
            if not isinstance(getattr(self, field), expected):
                raise TypeError(
                    f"--{field.replace('_', '-')} must be {expected.__name__}"
                )


@dataclass(frozen=True)
class PrimaryConfig(_BaseConfig):
    switch_b_mac: str

    def __post_init__(self):
        super().__post_init__()
        if not isinstance(self.switch_b_mac, str):
            raise TypeError("--switch-b-mac is required for primary role")


@dataclass(frozen=True)
class SecondaryConfig(_BaseConfig):
    pass


# --- pyroute2 helpers ---


def _disable_ipv6(ifname: str):
    """procfs 直書き (sysctl subprocess の代替)"""
    with open(f"/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6", "w") as f:
        f.write("1")


@contextmanager
def _link_create(ipr: IPRoute, ifname: str, **kwargs) -> Generator[int, None, None]:
    """インターフェースを作成し、yield で ifindex を返す。with 離脱時に自動削除。"""
    ipr.link("add", ifname=ifname, **kwargs)
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        raise RuntimeError(f"Failed to create interface {ifname!r}")
    try:
        yield idx[0]
    finally:
        ipr.link("del", index=idx[0])


@contextmanager
def _veth_create(
    ipr: IPRoute, ifname: str, peer: str
) -> Generator[tuple[int, int], None, None]:
    """veth pair を作成し (ifindex, peer_ifindex) を yield する。with 離脱時に自動削除。"""
    with _link_create(ipr, ifname, kind="veth", peer=peer) as idx:
        peer_idx = ipr.link_lookup(ifname=peer)
        if not peer_idx:
            raise RuntimeError(f"Failed to create peer interface {peer!r}")
        yield (idx, peer_idx[0])


@contextmanager
def _tc_ingress_redirect(
    ipr: IPRoute, src_idx: int, dst_idx: int
) -> Generator[None, None, None]:
    """tc ingress qdisc + u32 mirred redirect を設定し、with 離脱時に削除。"""
    ipr.tc("add", "ingress", index=src_idx)
    ipr.tc(
        "add-filter",
        "u32",
        index=src_idx,
        parent=0xFFFF0000,
        protocol=protocols.ETH_P_ALL,
        keys=["0x0/0x0+0"],
        target=TC_H_ROOT,
        action={
            "kind": "mirred",
            "direction": "egress",
            "action": "redirect",
            "ifindex": dst_idx,
        },
    )
    try:
        yield
    finally:
        ipr.tc("del", "ingress", index=src_idx)


# --- Network infrastructure ---


def _ifindex(ipr: IPRoute, ifname: str) -> int | None:
    idx = ipr.link_lookup(ifname=ifname)
    return idx[0] if idx else None


def cleanup_stale_interfaces(ipr: IPRoute):
    """前回の異常終了で残った LDN インターフェースを削除する。"""
    # nl80211 仮想 IF も RTM_DELLINK で削除可能
    for ifname in [IF_LDN, IF_LDN_MON, IF_LDN_TAP, IF_RELAY_STA, IF_BRIDGE, IF_GRETAP]:
        idx = _ifindex(ipr, ifname)
        if idx is not None:
            try:
                ipr.link("del", index=idx)
            except NetlinkError:
                pass
    # tc ingress qdisc (ldn が既に削除されていれば不要だが念のため)
    idx = _ifindex(ipr, IF_LDN)
    if idx is not None:
        try:
            ipr.tc("del", "ingress", index=idx)
        except NetlinkError:
            pass
    # policy routing 残骸
    try:
        ipr.rule("del", table=100)
    except NetlinkError:
        pass
    try:
        ipr.flush_routes(table=100)
    except NetlinkError:
        pass


@contextmanager
def setup_tunnel(
    ipr: IPRoute, local_ip, remote_ip
) -> Generator[tuple[int, int], None, None]:
    """GRETAP トンネル + br-ldn ブリッジを構築し (idx_gretap, idx_br) を yield する。"""
    with (
        # GRETAP tunnel: key 1, nopmtudisc
        # gre_iflags/gre_oflags=0x2000 = GRE_KEY flag (big-endian)
        _link_create(
            ipr,
            IF_GRETAP,
            kind="gretap",
            gre_local=local_ip,
            gre_remote=remote_ip,
            gre_ikey=1,
            gre_okey=1,
            gre_iflags=0x2000,
            gre_oflags=0x2000,
            gre_pmtudisc=0,
        ) as idx_gretap,
        _link_create(
            ipr, IF_BRIDGE, kind="bridge", br_stp_state=0, br_forward_delay=0
        ) as idx_br,
    ):
        ipr.link("set", index=idx_gretap, mtu=1500, state="up")
        ipr.link("set", index=idx_br, state="up")

        ipr.link("set", index=idx_gretap, master=idx_br)

        _disable_ipv6(IF_BRIDGE)

        yield (idx_gretap, idx_br)


@contextmanager
def setup_station_relay(
    ipr: IPRoute, idx_gretap: int, idx_br: int, idx_ldn: int, ifname=IF_LDN
) -> Generator[None, None, None]:
    """Primary: station IF と bridge 間の L2 リレーを tc mirred redirect で構成する。

    managed-mode WiFi STA は直接 bridge に追加できない (EOPNOTSUPP) ため、
    veth pair + tc ingress redirect で双方向パケットフォワーディングを行う。

    MAC learning を無効化し、全フレームをフラッディングさせる。
    bridge ポートが 2 つ (relay-br + gretap1) のみなので、
    フレームは到着ポート以外の全ポート (= もう 1 つ) に転送される。ループなし。

    with 離脱時に veth pair と tc ingress qdisc を自動削除。
    """
    with _veth_create(ipr, IF_RELAY_STA, IF_RELAY_BR) as (
        idx_relay_sta,
        idx_relay_br,
    ):
        ipr.link("set", index=idx_relay_sta, state="up")
        ipr.link("set", index=idx_relay_br, state="up")

        ipr.link("set", index=idx_relay_br, master=idx_br)

        # MAC learning 無効化 — 全フレームをフラッディング
        ipr.brport("set", index=idx_relay_br, learning=0)
        ipr.brport("set", index=idx_gretap, learning=0)

        _disable_ipv6(ifname)
        _disable_ipv6(IF_RELAY_STA)
        _disable_ipv6(IF_RELAY_BR)

        # tc ingress redirect: 双方向
        with (
            _tc_ingress_redirect(ipr, idx_ldn, idx_relay_sta),
            _tc_ingress_redirect(ipr, idx_relay_sta, idx_ldn),
        ):
            yield


def add_tap_to_bridge(
    ipr: IPRoute, idx_gretap: int, idx_br: int, idx_tap: int, idx_mon: int
):
    """Secondary: TAP を br-ldn に追加する。MAC learning 無効化でフラッディング強制。"""

    ipr.link("set", index=idx_tap, master=idx_br)

    ipr.brport("set", index=idx_tap, learning=0)
    ipr.brport("set", index=idx_gretap, learning=0)

    _disable_ipv6(IF_LDN_TAP)

    # 802.11 フレームは Ethernet より大きい (header 24 + CCMP 8 + SNAP 8 + MIC 8 = +34 bytes)
    # MTU 1500 だと大きい Pia パケットの変換後フレームが EMSGSIZE になる
    ipr.link("set", index=idx_mon, mtu=2304)


# --- Monkey-patching (Secondary only) ---


def patch_secondary_network(ipr: IPRoute, network, net_msg, idx_tap: int):
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
    ipr.flush_addr(index=idx_tap)
    ipr.addr(
        "add",
        index=idx_tap,
        address=f"169.254.{network_id}.254",
        prefixlen=24,
        broadcast=f"169.254.{network_id}.255",
    )

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


def inject_virtual_participant(
    network, index, ip, mac_str, name, app_version, platform
):
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
        participants.append(
            {
                "index": i,
                "ip": p.ip_address,
                "mac": str(p.mac_address),
                "connected": p.connected,
                "name": p.name.hex() if p.name else "",
                "app_version": p.app_version,
                "platform": p.platform,
            }
        )
    # 8 エントリに満たない場合はパディング
    for i in range(len(info.participants), 8):
        participants.append(
            {
                "index": i,
                "ip": "",
                "mac": "00:00:00:00:00:00",
                "connected": False,
                "name": "",
                "app_version": 0,
                "platform": 0,
            }
        )

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


def make_create_param(keys, phy, msg, passphrase):
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
    param.password = passphrase
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


async def scan_ldn(keys, phy):
    for attempt in range(10):
        print(f"Scan {attempt + 1}/10...", end=" ", flush=True)
        networks = await ldn.scan(
            keys=keys,
            phyname=phy,
            ifname=IF_LDN,
            channels=[1, 6, 11],
            dwell_time=0.130,
            protocols=[1, 3],
        )
        print(f"{len(networks)} found")
        if networks:
            return networks[0]
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
                    print(f"  [PRIMARY JOIN] idx={event.index} (self, skipping relay)")
                    continue
                print(
                    f"  [PRIMARY JOIN] idx={event.index}"
                    f" {p.name.decode(errors='replace')}"
                    f" IP={p.ip_address} MAC={p.mac_address}"
                )
                await send_msg(peer_stream, make_join_msg(event.index, p))
            elif isinstance(event, ldn.LeaveEvent):
                p = event.participant
                print(
                    f"  [PRIMARY LEAVE] idx={event.index}"
                    f" {p.name.decode(errors='replace')}"
                )
                await send_msg(peer_stream, make_leave_msg(event.index))
            elif isinstance(event, ldn.ApplicationDataChanged):
                print(f"  [APP_DATA] {len(event.new)} bytes")
                await send_msg(
                    peer_stream,
                    {
                        "type": "app_data",
                        "data": event.new.hex(),
                    },
                )
            elif isinstance(event, ldn.AcceptPolicyChanged):
                print(f"  [ACCEPT] {event.old} -> {event.new}")
                await send_msg(
                    peer_stream,
                    {
                        "type": "accept",
                        "policy": event.new,
                    },
                )
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
            print(
                f"  [SECONDARY JOIN] idx={event.index}"
                f" {p.name.decode(errors='replace')}"
                f" IP={p.ip_address} MAC={p.mac_address}"
            )
            await send_msg(peer_stream, make_join_msg(event.index, p))
        elif isinstance(event, ldn.LeaveEvent):
            p = event.participant
            print(
                f"  [SECONDARY LEAVE] idx={event.index}"
                f" {p.name.decode(errors='replace')}"
            )
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
            print(f"  [REMOTE LEAVE] idx={msg['index']} (continuing relay)")
        elif msg["type"] == "join":
            # 追加の参加者 (将来対応)
            print(
                f"  [REMOTE JOIN] idx={msg['index']}"
                f" IP={msg['ip']} MAC={msg['mac']}"
                f" (additional participant, not yet supported)"
            )


async def handle_peer_messages_secondary(network, reader):
    """Secondary: Primary からの JOIN/LEAVE/APP_DATA/ACCEPT を処理する。"""
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            print("  [CTRL] Primary disconnected")
            break

        if msg["type"] == "join":
            print(f"  [REMOTE JOIN] idx={msg['index']} IP={msg['ip']} MAC={msg['mac']}")
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
            print(
                f"  [CONNECTED] Primary STA assigned: idx={primary_idx} IP={primary_ip}"
            )
            # Switch B の IP と一致するか確認
            for idx, p in enumerate(network._network.participants):
                if p.connected and idx > 0:
                    if p.ip_address != primary_ip:
                        print(
                            f"  [WARN] IP mismatch! Switch B has"
                            f" {p.ip_address}, Primary expects"
                            f" {primary_ip}"
                        )
                    else:
                        print(f"  [OK] IP match: {p.ip_address}")


# --- Main flows ---


async def run_primary(ipr: IPRoute, config: PrimaryConfig):
    keys = ldn.load_keys(config.keys)

    # 1. Scan (STA 接続はしない — scan 結果から全情報を取得)
    print("=== 1. Scan for LDN network ===")
    print("Switch A でローカル通信の部屋を作ってください")
    print()
    info = await scan_ldn(keys, config.phy)
    if info is None:
        print("LDN network not found.")
        return

    host = info.participants[0]
    host_ip = host.ip_address
    network_id = int(host_ip.split(".")[2])
    print(
        f"\n  ch={info.channel} proto={info.protocol} ver={info.version}"
        f" app_ver={info.app_version}"
    )
    print(f"  BSSID={info.address}")
    print(f"  Host: IP={host_ip} MAC={host.mac_address}")
    print(f"  network_id={network_id}")
    print()

    # 2. GRETAP tunnel + bridge
    print("=== 2. GRETAP tunnel + bridge ===")
    with setup_tunnel(ipr, config.local, config.remote) as (idx_gretap, idx_br):
        print()

        # 3. STA 接続 (Switch B 参加前に relay を完成させる)
        print(f"=== 3. Connecting to Switch A as {config.switch_b_mac} ===")
        param = ldn.ConnectNetworkParam()
        param.keys = keys
        param.phyname = config.phy
        param.network = info
        param.password = config.ldn_passphrase or b""
        param.name = b"LDN-Tunnel"
        param.address = ldn.MACAddress(config.switch_b_mac)

        max_connect_attempts = 3
        for attempt in range(max_connect_attempts):
            if attempt > 0:
                print(f"\n  Retry {attempt + 1}/{max_connect_attempts} in 2 seconds...")
                await trio.sleep(2)
                # Re-scan for fresh NetworkInfo
                print("  Re-scanning...")
                fresh_info = await scan_ldn(keys, config.phy)
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
                    print(f"  MAC: {config.switch_b_mac} (spoofed)")
                    print()

                    # 4. Relay 構築 (Switch B 参加前に完成)
                    print("=== 4. Setting up relay ===")
                    with setup_station_relay(ipr, idx_gretap, idx_br, sta.ifindex):
                        print()

                        # 5. Secondary 待機
                        listeners = await trio.open_tcp_listeners(
                            config.control_port, host=config.local
                        )
                        try:
                            print(
                                f"=== 5. Waiting for secondary on port {config.control_port} ==="
                            )
                            print(
                                f"  Listening on {config.local}:{config.control_port}"
                            )

                            peer_stream = await listeners[0].accept()
                            reader = LineReader(peer_stream)
                            print("  Secondary connected!")

                            # 6. NETWORK + CONNECTED 送信
                            net_msg = make_network_msg_from_scan(info)
                            await send_msg(peer_stream, net_msg)
                            await send_msg(
                                peer_stream,
                                {
                                    "type": "connected",
                                    "index": sta_index,
                                    "ip": sta_ip,
                                },
                            )
                            print("  NETWORK + CONNECTED sent, waiting for READY...")

                            try:
                                ready_msg = await recv_msg(reader)
                            except (trio.ClosedResourceError, trio.EndOfChannel):
                                print("  Secondary disconnected before READY")
                                return
                            assert ready_msg["type"] == "ready", (
                                f"Expected 'ready', got {ready_msg}"
                            )
                            print("  Secondary is ready!")
                            print()

                            print("=== Ready ===")
                            print("Switch B で「ローカル通信」から参加してください")
                            print("Pia 通信が透過的にリレーされます")
                            print("Ctrl+C で終了")
                            print()

                            # 7. Event loop
                            async with trio.open_nursery() as nursery:
                                nursery.start_soon(
                                    handle_primary_events,
                                    sta,
                                    peer_stream,
                                    config.switch_b_mac,
                                )

                                async def _wait_secondary(
                                    reader=reader,
                                ):
                                    await handle_peer_messages_primary(reader)
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


async def run_secondary(ipr: IPRoute, config: SecondaryConfig):
    keys = ldn.load_keys(config.keys)

    # 1. GRETAP + bridge
    print("=== 1. GRETAP tunnel + bridge ===")
    with setup_tunnel(ipr, config.local, config.remote) as (idx_gretap, idx_br):
        print()

        # 2. Connect to primary
        print(
            f"=== 2. Connecting to primary at {config.remote}:{config.control_port} ==="
        )
        peer_stream = await trio.open_tcp_stream(config.remote, config.control_port)
        reader = LineReader(peer_stream)
        print("  Connected!")

        # 3. Receive NETWORK
        net_msg = await recv_msg(reader)
        assert net_msg["type"] == "network", f"Expected 'network', got {net_msg}"
        network_id = net_msg["network_id"]
        host_p = net_msg["participants"][0]
        print(
            f"  Received NETWORK:"
            f" game_id={net_msg['local_communication_id']:#018x}"
            f" ch={net_msg['channel']} network_id={network_id}"
        )
        print(f"  Host (Switch A): IP={host_p['ip']} MAC={host_p['mac']}")
        print()

        # 4. Host proxy LDN
        print("=== 3. Hosting proxy LDN network ===")
        param = make_create_param(
            keys, config.phy, net_msg, config.ldn_passphrase or b""
        )

        async with ldn.create_network(param) as network:
            # 5. Patch: Switch A のプロキシとして構成
            patch_secondary_network(ipr, network, net_msg, network.ifindex_tap)

            # 6. Bridge TAP
            add_tap_to_bridge(
                ipr, idx_gretap, idx_br, network.ifindex_tap, network.ifindex_monitor
            )

            # 7. Signal ready
            await send_msg(peer_stream, {"type": "ready"})

            print(f"  subnet: 169.254.{network_id}.0/24")
            print(f"  participant 0 (Switch A): {host_p['ip']} {host_p['mac']}")
            print()
            print("=== Ready ===")
            print("Switch B で「ローカル通信」から参加してください")
            print("Ctrl+C で終了")
            print()

            async with trio.open_nursery() as nursery:
                nursery.start_soon(handle_secondary_events, network, peer_stream)
                nursery.start_soon(handle_peer_messages_secondary, network, reader)


async def main():
    parser = argparse.ArgumentParser(description="LDN Tunnel Node v4")
    parser.add_argument("keys", help="prod.keys のパス")
    parser.add_argument(
        "--role",
        required=True,
        choices=["primary", "secondary"],
        help="primary: MAC スプーフ STA リレー、secondary: AP プロキシ",
    )
    parser.add_argument("--local", required=True, help="ローカル WireGuard IP")
    parser.add_argument("--remote", required=True, help="リモート WireGuard IP")
    parser.add_argument("--phy", required=True, help="Wi-Fi phy 名 (例: phy1)")
    parser.add_argument(
        "--switch-b-mac",
        default=None,
        help="Switch B の MAC アドレス (例: 64:B5:C6:1B:14:9B)",
    )
    parser.add_argument(
        "--ldn-passphrase",
        default=None,
        help="LDN パスフレーズを格納したバイナリファイルのパス (省略時は空). "
        "参照: https://github.com/kinnay/NintendoClients/wiki/LDN-Passphrases",
    )
    parser.add_argument(
        "--control-port",
        type=int,
        default=DEFAULT_CONTROL_PORT,
        help=f"Primary-Secondary 間の制御ポート (default: {DEFAULT_CONTROL_PORT})",
    )
    args = parser.parse_args()
    if args.ldn_passphrase is not None:
        with open(args.ldn_passphrase, "rb") as f:
            passphrase = f.read()
    else:
        passphrase = None

    common = dict(
        keys=args.keys,
        phy=args.phy,
        ldn_passphrase=passphrase,
        local=args.local,
        remote=args.remote,
        control_port=args.control_port,
    )

    with IPRoute() as ipr:
        cleanup_stale_interfaces(ipr)
        if args.role == "primary":
            config = PrimaryConfig(**common, switch_b_mac=args.switch_b_mac)
            await run_primary(ipr, config)
        else:
            config = SecondaryConfig(**common)
            await run_secondary(ipr, config)


if __name__ == "__main__":
    trio.run(main)
