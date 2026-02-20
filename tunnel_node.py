"""LDN Tunnel Node — Phase 2
Usage: sudo .venv/bin/python tunnel_node.py <prod.keys> --local <wg_ip> --remote <wg_ip>

両拠点で同じスクリプトを実行する。
1. GRETAP トンネル + Linux ブリッジを作成
2. MK8DX のパラメータをスキャンで取得
3. LDN ネットワークをホスト
4. ldn-tap をブリッジに接続
5. Switch が参加すると、対向の Switch と L2 で接続される
"""

import argparse
import subprocess
import sys

import trio
import ldn


MK8DX_GAME_ID = 0x0100152000022000
MK8DX_PASSWORD = b"MarioKart8Delux" + b"\x00" * 17


def run(cmd):
    print(f"  # {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def run_quiet(cmd):
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
    run_quiet(["ip", "link", "del", "br-ldn"])
    run_quiet(["ip", "link", "del", "gretap1"])


def add_tap_to_bridge():
    run(["ip", "link", "set", "ldn-tap", "master", "br-ldn"])
    run(["sysctl", "-w", "net.ipv6.conf.ldn-tap.disable_ipv6=1"])


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


async def main():
    parser = argparse.ArgumentParser(description="LDN Tunnel Node")
    parser.add_argument("keys", help="prod.keys のパス")
    parser.add_argument("--local", required=True, help="ローカル WireGuard IP")
    parser.add_argument("--remote", required=True, help="リモート WireGuard IP")
    parser.add_argument("--phy", default="phy1", help="Wi-Fi phy 名 (default: phy1)")
    args = parser.parse_args()

    keys = ldn.load_keys(args.keys)

    # 1. トンネル構築
    print("=== 1. GRETAP tunnel + bridge ===")
    setup_tunnel(args.local, args.remote)
    print(f"  tunnel: {args.local} <-> {args.remote}")
    print()

    try:
        # 2. スキャン
        print("=== 2. Scan ===")
        print("Switchでローカル通信の部屋を作ってください")
        print()
        info = await scan_mk8dx(keys, args.phy)
        if info is None:
            print("MK8DX network not found.")
            return

        print(f"\n  ch={info.channel} proto={info.protocol} ver={info.version}"
              f" app_ver={info.app_version}")
        print()

        # 3. Switch の部屋を閉じる
        print("=== 3. Switch側の部屋を閉じてEnterを押してください ===")
        await trio.to_thread.run_sync(input)

        # 4. ホスト
        print("=== 4. Hosting LDN network ===")
        param = ldn.CreateNetworkParam()
        param.keys = keys
        param.phyname = args.phy
        param.phyname_monitor = args.phy
        param.local_communication_id = info.local_communication_id
        param.scene_id = info.scene_id
        param.max_participants = info.max_participants
        param.application_data = info.application_data
        param.password = MK8DX_PASSWORD
        param.app_version = info.app_version
        param.version = info.version
        param.protocol = info.protocol
        param.name = b"LDN-Tunnel"
        param.channel = info.channel

        async with ldn.create_network(param) as network:
            # 5. TAP をブリッジに接続
            print("Network created!")
            add_tap_to_bridge()
            print()
            print("=== Ready ===")
            print("ldn-tap <-> br-ldn <-> gretap1 <-> WireGuard <-> remote")
            print()
            print("Switchで「ローカル通信」から参加してください")
            print("Ctrl+C で終了")
            print()

            while True:
                event = await network.next_event()
                if isinstance(event, ldn.JoinEvent):
                    p = event.participant
                    print(f"  [JOIN] {p.name.decode(errors='replace')}"
                          f" IP={p.ip_address} MAC={p.mac_address}")
                elif isinstance(event, ldn.LeaveEvent):
                    p = event.participant
                    print(f"  [LEAVE] {p.name.decode(errors='replace')}"
                          f" IP={p.ip_address}")
                elif isinstance(event, ldn.DisconnectEvent):
                    print(f"  [DISCONNECT] reason={event.reason}")
                    break
    finally:
        teardown_tunnel()


trio.run(main)
