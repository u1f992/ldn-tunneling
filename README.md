# ldn-tunneling

Bridge Nintendo Switch LDN sessions across the internet using MAC-spoofed STA relay (proof of concept).

The relayed LDN network is a real Wi-Fi session, so **OFW (stock firmware) consoles can join as-is** -- no CFW or modifications are needed on the participating Switch. However, two things must be prepared in advance:

1. **`prod.keys`** -- console key material, needed to decrypt and construct the encrypted LDN protocol frames (advertisements, authentication, data).
2. **LDN passphrase** -- a per-game 64-byte secret embedded in each title. Some games have [known passphrases](https://github.com/kinnay/NintendoClients/wiki/LDN-Passphrases); for the rest, you can extract them by logging the IPC calls inside an emulator:
   - [`ryujinx-ldn-log-passphrase.patch`](ryujinx-ldn-log-passphrase.patch) -- for Ryujinx (C#/.NET)
   - [`eden-ldn-log-passphrase.patch`](eden-ldn-log-passphrase.patch) -- for Eden (C++)

## Tested interfaces

A mac80211-based USB Wi-Fi adapter is required. The Secondary role additionally needs working monitor-mode TX injection (AF_PACKET `SOCK_RAW`), which limits the choice of drivers.

| Adapter | Chipset | Driver | Primary | Secondary | Availability |
|---|---|---|---|---|---|
| Netgear A6210 | MT7612U | mt76x2u | OK | OK | Discontinued; second-hand only |
| TP-Link Archer TX10UB Nano | RTL8851BU | rtw89 | OK | NG (TX injection silent-drops) | In production |
| TP-Link Archer TX20U Nano | RTL8832BU | rtw89 | OK | NG (TX injection silent-drops) | In production |

If you only need the Primary role, the widely available rtw89-based adapters work fine. For the Secondary role, an mt76x2u-based adapter (e.g. A6210 / MT7612U) is currently the only verified option.

**Note on Netgear A8000 (MT7921AU):** Although the A8000 is the successor to the A6210 and uses the same mt76 driver family (mt7921u), it has known monitor-mode TX injection bugs as of kernel 6.17 ([^gh-usbwifi-387], [^gh-mt76-839]). The hardware is capable in principle, but the driver issues currently prevent it from working for the Secondary role.

[^gh-usbwifi-387]: https://github.com/morrownr/USB-WiFi/issues/387
[^gh-mt76-839]: https://github.com/openwrt/mt76/issues/839

## Setup

```shellsession
$ iw dev
phy#1
        Interface wlx94a67e5d7030
                ...
$ rfkill list
2: phy1: Wireless LAN
        Soft blocked: yes
...
$ # If soft blocked, unblock first
$ rfkill unblock 2

$ # Prevent NetworkManager from interfering with the adapter and LDN interfaces
$ sudo tee /etc/NetworkManager/conf.d/99-ldn-unmanaged.conf << 'EOF'
[device-ldn]
match-device=interface-name:wlx*;interface-name:ldn
managed=0
EOF
$ sudo systemctl reload NetworkManager

$ # setcap cannot operate on symlinks; use --copies to place a real binary.
$ # uv does not support --copies yet: https://github.com/astral-sh/uv/issues/17754
$ python3 -m venv --copies .venv
$ # CAP_NET_ADMIN: netlink (nl80211, rtnetlink, tc), /dev/net/tun ioctl, /proc/sys/net writes
$ # CAP_NET_RAW:   AF_PACKET SOCK_RAW sockets (monitor-mode frame I/O)
$ sudo setcap cap_net_admin,cap_net_raw+ep .venv/bin/python
$ uv sync

$ # LDN passphrases for some games have been revealed: https://github.com/kinnay/NintendoClients/wiki/LDN-Passphrases
$ printf 'MarioKart8Delux\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > mk8dx.bin

$ # --local/--remote take any mutually reachable IPs. Use WireGuard or another VPN if crossing the WAN.
$ # Allow the control channel on the Primary side (GRETAP is handled by conntrack).
$ sudo ufw allow from 10.8.0.0/24 to any port 39571 proto tcp

$ # Primary
$ .venv/bin/python main.py prod.keys --role primary --local 10.8.0.1 --remote 10.8.0.2 --phy phy1 --switch-b-mac 64:B5:C6:1B:14:9B --ldn-passphrase mk8dx.bin

$ # Secondary
$ .venv/bin/python main.py prod.keys --role secondary --local 10.8.0.2 --remote 10.8.0.1 --phy phy1 --ldn-passphrase mk8dx.bin
```

## Cleanup

If the process is killed ungracefully (e.g. `kill -9`, SSH disconnect), virtual interfaces may be left behind. The next run cleans them up automatically, but you can also do it manually:

```shellsession
$ .venv/bin/python -c "from pyroute2 import IPRoute; import main; ipr = IPRoute(); main.cleanup_stale_interfaces(ipr); ipr.close()"
```
