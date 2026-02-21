"""LDN ホストテスト — Step 4
Usage: sudo .venv/bin/python host_test.py <prod.keys のパス>

1. まずSwitchが作ったMK8DXネットワークをスキャンして実パラメータを取得
2. Switchの部屋を閉じてもらう
3. 取得したパラメータでLinux PCがLDNネットワークをホスト
4. Switchから「ローカル通信」で発見・参加できるか確認
"""

import sys
import trio
import ldn


MK8DX_GAME_ID = 0x0100152000022000
MK8DX_PASSWORD = b"MarioKart8Delux" + b"\x00" * 17


async def capture_network_params(keys):
    """MK8DXネットワークをスキャンして実パラメータを取得"""
    for attempt in range(10):
        print(f"Scan attempt {attempt + 1}/10...", end=" ", flush=True)
        networks = await ldn.scan(
            keys=keys,
            phyname="phy8",
            ifname="ldn",
            channels=[1, 6, 11],
            dwell_time=0.130,
            protocols=[1, 3],
        )
        print(f"{len(networks)} found")

        for net in networks:
            if net.local_communication_id == MK8DX_GAME_ID:
                return net

    return None


async def main():
    if len(sys.argv) < 2:
        print("Usage: sudo .venv/bin/python host_test.py <path/to/prod.keys>")
        sys.exit(1)

    keys = ldn.load_keys(sys.argv[1])

    # Phase 1: スキャンしてMK8DXの実パラメータを取得
    print("=== Phase 1: Capturing MK8DX network parameters ===")
    print("Switchでローカル通信の部屋を作った状態にしてください")
    print()

    info = await capture_network_params(keys)
    if info is None:
        print("MK8DX network not found.")
        return

    print(f"\nCaptured parameters:")
    print(f"  Game ID:          {info.local_communication_id:#018x}")
    print(f"  Scene ID:         {info.scene_id}")
    print(f"  Channel:          {info.channel}")
    print(f"  Protocol:         {info.protocol}")
    print(f"  Version:          {info.version}")
    print(f"  App Version:      {info.app_version}")
    print(f"  Max Participants: {info.max_participants}")
    print(f"  Security Mode:    {info.security_mode}")
    print(f"  App Data length:  {len(info.application_data)} bytes")
    print(f"  Accept Policy:    {info.accept_policy}")
    print()

    # Phase 2: ユーザーにSwitch側の部屋を閉じてもらう
    print("=== Phase 2: Switch側の部屋を閉じてください ===")
    print("閉じたらEnterを押してください...")
    await trio.to_thread.run_sync(input)

    # Phase 3: Linux PCがホスト
    print("=== Phase 3: Hosting LDN network ===")
    param = ldn.CreateNetworkParam()
    param.keys = keys
    param.ifname = "wlx94a67e5d7030"
    param.phyname = "phy8"
    param.phyname_monitor = "phy8"
    param.local_communication_id = info.local_communication_id
    param.scene_id = info.scene_id
    param.max_participants = info.max_participants
    param.application_data = info.application_data
    param.password = MK8DX_PASSWORD
    param.app_version = info.app_version
    param.version = info.version
    param.protocol = info.protocol
    param.name = b"LDN-Host"
    param.channel = info.channel

    print(f"Hosting on channel {info.channel}...")
    print(f"TAP interface: {param.ifname_tap}")
    print()

    async with ldn.create_network(param) as network:
        print("Network created!")
        print("Switchで「ローカル通信」を開いて、部屋が見えるか確認してください")
        print("Listening for events... (Ctrl+C to stop)")
        print()

        while True:
            event = await network.next_event()
            if isinstance(event, ldn.JoinEvent):
                p = event.participant
                print(f"  [JOIN] {p.name.decode(errors='replace')} "
                      f"(IP: {p.ip_address}, MAC: {p.mac_address})")
            elif isinstance(event, ldn.LeaveEvent):
                p = event.participant
                print(f"  [LEAVE] {p.name.decode(errors='replace')} "
                      f"(IP: {p.ip_address})")
            elif isinstance(event, ldn.DisconnectEvent):
                print(f"  [DISCONNECT] reason={event.reason}")
                break


trio.run(main)
