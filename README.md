# ldn-tunneling

Bridge Nintendo Switch LDN sessions across the internet using MAC-spoofed STA relay (proof of concept)

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
