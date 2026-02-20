"""LDN 参加テスト — Step 3
Usage: sudo .venv/bin/python join_test.py <prod.keys のパス>

マリオカート8DXのローカル通信に参加し、TAPインターフェースの状態を確認する。
"""

import sys
import trio
import socket
import ldn


MK8DX_GAME_ID = 0x0100152000022000
MK8DX_PASSWORD = b"MarioKart8Delux" + b"\x00" * 17  # 32 bytes total


async def find_network(keys):
    """マリオカート8DXのLDNネットワークを探す"""
    for attempt in range(10):
        print(f"Scan attempt {attempt + 1}/10...", end=" ", flush=True)
        networks = await ldn.scan(
            keys=keys,
            phyname="phy1",
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


async def receive_packets():
    """ネットワーク上のUDPパケットを受信して表示"""
    s = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    await s.bind(("", 12345))
    while True:
        data, addr = await s.recvfrom(4096)
        print(f"  [UDP] {len(data)} bytes from {addr}")


async def main():
    if len(sys.argv) < 2:
        print("Usage: sudo .venv/bin/python join_test.py <path/to/prod.keys>")
        sys.exit(1)

    keys = ldn.load_keys(sys.argv[1])

    # 1. スキャン
    print("=== Scanning for Mario Kart 8 DX LDN network ===")
    info = await find_network(keys)
    if info is None:
        print("MK8DX network not found.")
        return

    print(f"\nFound MK8DX network:")
    print(f"  MAC:       {info.address}")
    print(f"  Channel:   {info.channel}")
    print(f"  Protocol:  {info.protocol}")
    print(f"  Version:   {info.version}")
    print(f"  Players:   {info.num_participants}/{info.max_participants}")
    print(f"  SSID:      {info.ssid.hex()}")
    print()

    # 2. 参加
    print("=== Joining network ===")
    param = ldn.ConnectNetworkParam()
    param.keys = keys
    param.network = info
    param.phyname = "phy1"
    param.name = b"LDN-Tunnel"
    param.password = MK8DX_PASSWORD
    param.app_version = info.app_version

    async with ldn.connect(param) as network:
        print("Connected!")
        print(f"  My IP:     {network.participant().ip_address}")
        print(f"  My MAC:    {network.participant().mac_address}")
        print(f"  Broadcast: {network.broadcast_address()}")
        print()
        print("Listening for events and packets... (Ctrl+C to stop)")
        print()

        async with trio.open_nursery() as nursery:
            nursery.start_soon(receive_packets)

            while True:
                event = await network.next_event()
                if isinstance(event, ldn.JoinEvent):
                    p = event.participant
                    print(f"  [JOIN] {p.name.decode(errors='replace')} ({p.ip_address})")
                elif isinstance(event, ldn.LeaveEvent):
                    p = event.participant
                    print(f"  [LEAVE] {p.name.decode(errors='replace')} ({p.ip_address})")
                elif isinstance(event, ldn.DisconnectEvent):
                    print(f"  [DISCONNECT] reason={event.reason}")
                    break

            nursery.cancel_scope.cancel()

    print("Disconnected.")


trio.run(main)
