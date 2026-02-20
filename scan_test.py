"""LDN スキャンテスト — Step 2
Usage: sudo .venv/bin/python scan_test.py <prod.keys のパス>
"""

import sys
import trio
import ldn

ROUNDS = 5
DWELL_TIME = 0.130  # 130ms (アドバタイズ間隔100msより長め)
CHANNELS = [1, 6, 11]


async def main():
    if len(sys.argv) < 2:
        print("Usage: sudo .venv/bin/python scan_test.py <path/to/prod.keys>")
        sys.exit(1)

    keys = ldn.load_keys(sys.argv[1])

    print(f"Scanning for LDN networks on phy1 (A6210)")
    print(f"Channels: {CHANNELS}  |  Dwell: {DWELL_TIME*1000:.0f}ms  |  Rounds: {ROUNDS}")
    print("---")

    all_found = {}

    for i in range(ROUNDS):
        print(f"Round {i + 1}/{ROUNDS}...", end=" ", flush=True)
        networks = await ldn.scan(
            keys=keys,
            phyname="phy1",
            ifname="ldn",
            channels=CHANNELS,
            dwell_time=DWELL_TIME,
            protocols=[1, 3],
        )
        print(f"{len(networks)} found")

        for net in networks:
            key = (str(net.address), net.local_communication_id)
            all_found[key] = net

    print("---")

    if not all_found:
        print("No LDN networks found in any round.")
        print()
        print("チェックリスト:")
        print("  - Switchで「ローカル通信」の部屋を作っていますか？（LANプレイではなく）")
        print("  - Switchは近く（数メートル以内）にありますか？")
        print("  - rfkill list でphy1がunblockされていますか？")
        return

    print(f"\n{len(all_found)} network(s) found:\n")
    for i, net in enumerate(all_found.values()):
        print(f"Network {i + 1}:")
        print(f"  MAC:          {net.address}")
        print(f"  Game ID:      {net.local_communication_id:#018x}")
        print(f"  Channel:      {net.channel} ({net.band} GHz)")
        print(f"  Protocol:     {net.protocol}")
        print(f"  Version:      {net.version}")
        print(f"  Players:      {net.num_participants}/{net.max_participants}")
        print(f"  Security:     {net.security_mode}")
        for p in net.participants:
            if p.connected:
                print(f"    - {p.name} (IP: {p.ip_address}, MAC: {p.mac_address})")
        print()


trio.run(main)
