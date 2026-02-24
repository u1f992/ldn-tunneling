r"""LDN Tunnel Node v4 - MAC-spoofed STA relay

v4 MAC-spoof relay architecture:
  Primary (PC A):   Connects to Switch A's AP as STA using Switch B's MAC.
                    Switch A sees Switch B as a direct participant.
                    Pia AES-GCM nonces (CRC32 includes MAC) match,
                    so encrypted traffic is transparently relayed.
  Secondary (PC B): Hosts a cloned AP via ldn.create_network().
                    Participant 0 is rewritten to Switch A's info,
                    so Switch B sees Switch A as the host.

  Flow (--switch-b-mac pre-specified; relay is ready before Switch B joins):
    1. Primary: scan -> obtain NETWORK info
    2. Primary: tunnel + bridge + STA connect (Switch B MAC) + relay setup
    3. Primary: wait for Secondary -> send NETWORK + CONNECTED
    4. Secondary: create AP -> READY
    5. Switch B joins -> Pia traffic is relayed immediately
"""

import argparse
from contextlib import contextmanager
import dataclasses
from dataclasses import dataclass, field
import ipaddress
import json
import logging
import socket
import struct
import types
from typing import Any, Generator

import trio
import ldn
from pyroute2 import IPRoute, protocols
from pyroute2.netlink.rtnl import TC_H_ROOT

TRACE = 5
logging.addLevelName(TRACE, "TRACE")
logger = logging.getLogger(__name__)


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
    keys: dict[str, bytes]
    phy: str
    ldn_passphrase: bytes | None
    local: str
    remote: str
    control_port: int

    def __post_init__(self):
        for name, expected in {
            "keys": dict,
            "phy": str,
            "ldn_passphrase": (bytes, type(None)),
            "local": str,
            "remote": str,
            "control_port": int,
        }.items():
            if not isinstance(getattr(self, name), expected):
                raise TypeError(
                    f"--{name.replace('_', '-')} must be {expected.__name__}"
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


class InvalidMessageError(Exception):
    """Received a control-channel message that could not be decoded."""


# --- Control messages ---


@dataclass(frozen=True)
class NetworkParticipant:
    index: int
    ip: str
    mac: str
    connected: bool
    name: str
    app_version: int
    platform: int


@dataclass(frozen=True)
class NetworkMsg:
    type: str = field(init=False, default="network")
    network_id: int
    local_communication_id: int
    scene_id: int
    channel: int
    protocol: int
    version: int
    app_version: int
    max_participants: int
    security_mode: int
    accept_policy: int
    application_data: str
    server_random: str
    ssid: str
    participants: tuple[
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
        NetworkParticipant,
    ]

    def __post_init__(self) -> None:
        # LDN has exactly 8 participant slots (CreateNetworkParam.max_participants).
        # See https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol
        if len(self.participants) != ldn.CreateNetworkParam.max_participants:
            raise ValueError(
                f"participants must have {ldn.CreateNetworkParam.max_participants}"
                f" elements, got {len(self.participants)}"
            )


@dataclass(frozen=True)
class ConnectedMsg:
    type: str = field(init=False, default="connected")
    index: int
    ip: str


@dataclass(frozen=True)
class ReadyMsg:
    type: str = field(init=False, default="ready")


@dataclass(frozen=True)
class JoinMsg:
    type: str = field(init=False, default="join")
    index: int
    ip: str
    mac: str
    name: str
    app_version: int
    platform: int


@dataclass(frozen=True)
class LeaveMsg:
    type: str = field(init=False, default="leave")
    index: int


@dataclass(frozen=True)
class AppDataMsg:
    type: str = field(init=False, default="app_data")
    data: str


@dataclass(frozen=True)
class AcceptMsg:
    type: str = field(init=False, default="accept")
    policy: int


ControlMsg = (
    NetworkMsg | ConnectedMsg | ReadyMsg | JoinMsg | LeaveMsg | AppDataMsg | AcceptMsg
)

_MSG_REGISTRY: dict[str, type] = {
    "network": NetworkMsg,
    "connected": ConnectedMsg,
    "ready": ReadyMsg,
    "join": JoinMsg,
    "leave": LeaveMsg,
    "app_data": AppDataMsg,
    "accept": AcceptMsg,
}


def _encode_msg(msg: ControlMsg) -> bytes:
    return json.dumps(dataclasses.asdict(msg)).encode() + b"\n"


def _decode_msg(d: dict[str, Any]) -> ControlMsg:
    tag = d.pop("type")
    cls = _MSG_REGISTRY.get(tag)
    if cls is None:
        raise InvalidMessageError(f"Unknown message type: {tag!r}")
    try:
        if cls is NetworkMsg:
            d["participants"] = tuple(
                NetworkParticipant(**p) for p in d["participants"]
            )
        return cls(**d)
    except Exception as e:
        raise InvalidMessageError(f"Malformed {tag!r} message: {e}") from e


# --- pyroute2 helpers ---


def _disable_ipv6(ifname: str):
    """Disable IPv6 on an interface via procfs (requires CAP_NET_ADMIN)."""
    with open(f"/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6", "w") as f:
        f.write("1")


@contextmanager
def _link_create(ipr: IPRoute, ifname: str, **kwargs) -> Generator[int, None, None]:
    """Create an interface and yield its ifindex. Auto-deleted on context exit."""
    ipr.link("add", ifname=ifname, **kwargs)
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        raise RuntimeError(f"Failed to create interface {ifname!r}")
    try:
        yield idx[0]
    finally:
        try:
            ipr.link("del", index=idx[0])
        except Exception:
            pass


@contextmanager
def _veth_create(
    ipr: IPRoute, ifname: str, peer: str
) -> Generator[tuple[int, int], None, None]:
    """Create a veth pair and yield (ifindex, peer_ifindex). Auto-deleted on context exit."""
    with _link_create(ipr, ifname, kind="veth", peer=peer) as idx:
        peer_idx = ipr.link_lookup(ifname=peer)
        if not peer_idx:
            raise RuntimeError(f"Failed to create peer interface {peer!r}")
        yield (idx, peer_idx[0])


@contextmanager
def _tc_ingress_redirect(
    ipr: IPRoute, src_idx: int, dst_idx: int
) -> Generator[None, None, None]:
    """Set up tc ingress qdisc + u32 mirred redirect. Removed on context exit."""
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
        try:
            ipr.tc("del", "ingress", index=src_idx)
        except Exception:
            pass


# --- Network infrastructure ---


def _ifindex(ipr: IPRoute, ifname: str) -> int | None:
    idx = ipr.link_lookup(ifname=ifname)
    return idx[0] if idx else None


def cleanup_stale_interfaces(ipr: IPRoute):
    """Remove LDN interfaces left over from a previous abnormal exit.

    Best-effort: individual deletion failures are ignored so the rest can proceed.
    Catches Exception (not bare except) to let KeyboardInterrupt / SystemExit propagate.
    """
    # nl80211 virtual interfaces can also be removed via RTM_DELLINK
    for ifname in [IF_LDN, IF_LDN_MON, IF_LDN_TAP, IF_RELAY_STA, IF_BRIDGE, IF_GRETAP]:
        idx = _ifindex(ipr, ifname)
        if idx is not None:
            try:
                ipr.link("del", index=idx)
            except Exception:
                pass
    # tc ingress qdisc (redundant if ldn was already deleted, but just in case)
    idx = _ifindex(ipr, IF_LDN)
    if idx is not None:
        try:
            ipr.tc("del", "ingress", index=idx)
        except Exception:
            pass
    # stale policy routing entries
    try:
        ipr.rule("del", table=100)
    except Exception:
        pass
    try:
        ipr.flush_routes(table=100)
    except Exception:
        pass


@contextmanager
def setup_tunnel(
    ipr: IPRoute, local_ip: str, remote_ip: str
) -> Generator[tuple[int, int], None, None]:
    """Build a GRETAP tunnel + br-ldn bridge and yield (idx_gretap, idx_br)."""
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
    ipr: IPRoute, idx_gretap: int, idx_br: int, idx_ldn: int, ifname: str
) -> Generator[None, None, None]:
    """Primary: set up L2 relay between the station IF and the bridge via tc mirred redirect.

    A managed-mode WiFi STA cannot be added to a bridge directly (EOPNOTSUPP),
    so a veth pair + tc ingress redirect provides bidirectional packet forwarding.

    MAC learning is disabled to force flooding on all frames.
    Since the bridge has only 2 ports (relay-br + gretap1),
    each frame is forwarded to the single other port. No loops.

    The veth pair and tc ingress qdiscs are auto-deleted on context exit.
    """
    with _veth_create(ipr, IF_RELAY_STA, IF_RELAY_BR) as (
        idx_relay_sta,
        idx_relay_br,
    ):
        ipr.link("set", index=idx_relay_sta, state="up")
        ipr.link("set", index=idx_relay_br, state="up")

        ipr.link("set", index=idx_relay_br, master=idx_br)

        # Disable MAC learning to flood all frames
        ipr.brport("set", index=idx_relay_br, learning=0)
        ipr.brport("set", index=idx_gretap, learning=0)

        _disable_ipv6(ifname)
        _disable_ipv6(IF_RELAY_STA)
        _disable_ipv6(IF_RELAY_BR)

        # Bidirectional tc ingress redirect
        with (
            _tc_ingress_redirect(ipr, idx_ldn, idx_relay_sta),
            _tc_ingress_redirect(ipr, idx_relay_sta, idx_ldn),
        ):
            yield


def add_tap_to_bridge(
    ipr: IPRoute, idx_gretap: int, idx_br: int, idx_tap: int, idx_mon: int
):
    """Secondary: add TAP to br-ldn. Disable MAC learning to force flooding."""

    ipr.link("set", index=idx_tap, master=idx_br)

    ipr.brport("set", index=idx_tap, learning=0)
    ipr.brport("set", index=idx_gretap, learning=0)

    _disable_ipv6(IF_LDN_TAP)

    # 802.11 frames are larger than Ethernet (header 24 + CCMP 8 + SNAP 8 + MIC 8 = +34 bytes).
    # With MTU 1500, large Pia packets cause EMSGSIZE after conversion.
    ipr.link("set", index=idx_mon, mtu=2304)


# --- Monkey-patching (Secondary only) ---


def patch_secondary_network(
    ipr: IPRoute, network: ldn.APNetwork, net_msg: NetworkMsg, idx_tap: int
):
    """Patch the Secondary APNetwork to act as a proxy for Switch A.

    1. Unify _network_id to Switch A's subnet ID
    2. Rewrite participant 0 to Switch A's info
    3. Set TAP IP to .254 so it does not conflict with Switch A's IP (.1)
    4. Restrict _register_participant to index 1+ (index 0 is reserved for Switch A)
    """
    network_id = net_msg.network_id
    host = net_msg.participants[0]

    # 1. Unify _network_id
    network._network_id = network_id

    # 2. participant 0 = Switch A
    p0 = network._network.participants[0]
    p0.ip_address = host.ip
    p0.mac_address = ldn.MACAddress(host.mac)
    p0.name = bytes.fromhex(host.name)
    p0.app_version = host.app_version
    p0.platform = host.platform

    # 3. Set TAP IP to .254
    ipr.flush_addr(index=idx_tap)
    ipr.addr(
        "add",
        index=idx_tap,
        address=f"169.254.{network_id}.254",
        prefixlen=24,
        broadcast=f"169.254.{network_id}.255",
    )

    # 4. Patch _register_participant (index 0 = Switch A reserved, 1-7 = Switch B+)
    async def patched_register(self, address, name, app_version, platform):
        target_index = None
        for idx in range(1, ldn.CreateNetworkParam.max_participants):
            if not self._network.participants[idx].connected:
                target_index = idx
                break

        if target_index is None:
            logger.warning("No free participant slot (index 1-7)")
            return

        self._peers.append(address)

        participant = ldn.ParticipantInfo(
            ip_address=f"169.254.{self._network_id}.{target_index + 1}",
            mac_address=address,
            connected=True,
            name=name,
            app_version=app_version,
            platform=platform,
        )
        self._network.participants[target_index] = participant
        self._network.num_participants += 1
        self._update_nonce()

        await self._interface.add_neighbor(
            participant.ip_address, participant.mac_address
        )
        await self._events.put(ldn.JoinEvent(target_index, participant))

    network._register_participant = types.MethodType(patched_register, network)  # type: ignore[method-assign]

    # Update advertisement
    network._update_nonce()


def inject_virtual_participant(
    network: ldn.APNetwork,
    index: int,
    ip: str,
    mac_str: str,
    name: bytes,
    app_version: int,
    platform: int,
):
    """Inject a remote participant as a virtual participant into the advertisement."""
    network._network.participants[index] = ldn.ParticipantInfo(
        ip_address=ip,
        mac_address=ldn.MACAddress(mac_str),
        connected=True,
        name=name,
        app_version=app_version,
        platform=platform,
    )
    network._network.num_participants += 1
    network._update_nonce()


def remove_virtual_participant(network: ldn.APNetwork, index: int):
    """Remove a virtual participant from the advertisement."""
    participant = network._network.participants[index]
    if participant.connected:
        participant.connected = False
        network._network.num_participants -= 1
        network._update_nonce()


# --- Control channel ---


class LineReader:
    """Wraps a trio.SocketStream to provide line-oriented reading."""

    def __init__(self, stream: trio.SocketStream):
        self.stream = stream
        self._buf = b""

    async def readline(self) -> bytes:
        while b"\n" not in self._buf:
            data = await self.stream.receive_some(4096)
            if not data:
                raise trio.EndOfChannel("Connection closed")
            self._buf += data
        line, self._buf = self._buf.split(b"\n", 1)
        return line


async def send_msg(stream: trio.SocketStream, msg: ControlMsg) -> None:
    await stream.send_all(_encode_msg(msg))


async def recv_msg(reader: LineReader) -> ControlMsg:
    line = await reader.readline()
    raw = json.loads(line)
    if not isinstance(raw, dict):
        raise InvalidMessageError(f"Non-object JSON: {raw!r}")
    return _decode_msg(raw)


# --- Message builders ---


def make_network_msg_from_scan(info: ldn.NetworkInfo) -> NetworkMsg:
    """Convert a scan NetworkInfo into a NetworkMsg.

    scan() returns a NetworkInfo parsed from an advertisement frame,
    so all information is available without STA association.
    """
    return NetworkMsg(
        # Extract the 3rd octet X from the host IP (169.254.X.1) as network_id
        network_id=ipaddress.IPv4Address(info.participants[0].ip_address).packed[2],
        local_communication_id=info.local_communication_id,
        scene_id=info.scene_id,
        channel=info.channel,
        protocol=info.protocol,
        version=info.version,
        app_version=info.app_version,
        max_participants=info.max_participants,
        security_mode=info.security_mode,
        accept_policy=info.accept_policy,
        application_data=info.application_data.hex(),
        server_random=info.server_random.hex(),
        ssid=info.ssid.hex(),
        participants=tuple(
            [
                NetworkParticipant(
                    index=i,
                    ip=p.ip_address,
                    mac=str(p.mac_address),
                    connected=p.connected,
                    name=p.name.hex() if p.name else "",
                    app_version=p.app_version,
                    platform=p.platform,
                )
                for i, p in enumerate(info.participants)
            ]
            + [
                NetworkParticipant(
                    index=i,
                    ip="",
                    mac="00:00:00:00:00:00",
                    connected=False,
                    name="",
                    app_version=0,
                    platform=0,
                )
                # LDN has exactly 8 participant slots (CreateNetworkParam.max_participants).
                # See https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol
                for i in range(
                    len(info.participants), ldn.CreateNetworkParam.max_participants
                )
            ]
        ),  # type: ignore[arg-type]
    )


def pick_secondary_channel(primary_channel: int) -> int:
    """Pick a different channel for the Secondary AP.

    Using the same channel causes Switch A to detect a MAC collision between
    the spoofed STA and the real Switch B, triggering disassociation.
    Picks from the 2.4 GHz non-overlapping channels (1, 6, 11).
    """
    non_overlapping = [1, 6, 11]
    candidates = [ch for ch in non_overlapping if ch != primary_channel]
    return candidates[0]


def make_create_param(
    keys: dict[str, bytes], phy: str, msg: NetworkMsg, passphrase: bytes
) -> ldn.CreateNetworkParam:
    """Build a CreateNetworkParam from a NetworkMsg."""
    return ldn.CreateNetworkParam(
        keys=keys,
        phyname=phy,
        phyname_monitor=phy,
        local_communication_id=msg.local_communication_id,
        scene_id=msg.scene_id,
        channel=pick_secondary_channel(msg.channel),
        protocol=msg.protocol,
        version=msg.version,
        app_version=msg.app_version,
        max_participants=msg.max_participants,
        security_mode=msg.security_mode,
        accept_policy=msg.accept_policy,
        application_data=bytes.fromhex(msg.application_data),
        server_random=bytes.fromhex(msg.server_random),
        ssid=bytes.fromhex(msg.ssid),
        password=passphrase,
        name=b"LDN-Tunnel",
    )


def make_join_msg(index: int, participant: ldn.ParticipantInfo) -> JoinMsg:
    return JoinMsg(
        index=index,
        ip=participant.ip_address,
        mac=str(participant.mac_address),
        name=participant.name.hex(),
        app_version=participant.app_version,
        platform=participant.platform,
    )


def make_leave_msg(index: int) -> LeaveMsg:
    return LeaveMsg(index=index)


# --- LDN scan ---


async def scan_ldn(keys: dict[str, bytes], phy: str) -> ldn.NetworkInfo | None:
    for attempt in range(10):
        networks = await ldn.scan(
            keys=keys,
            phyname=phy,
            ifname=IF_LDN,
            channels=[1, 6, 11],
            dwell_time=0.130,
            protocols=[1, 3],
        )
        logger.info("Scan %d/10: %d found", attempt + 1, len(networks))
        if networks:
            return networks[0]
    return None


# --- Event handling ---


async def handle_primary_events(
    sta: ldn.STANetwork, peer_stream: trio.SocketStream, relay_mac: str
) -> None:
    """Primary: monitor STANetwork events and forward them to Secondary via the control channel.

    relay_mac is our own STA MAC (= Switch B's MAC).
    Our own JoinEvent is filtered out and not forwarded to Secondary.
    """
    try:
        while True:
            event = await sta.next_event()
            match event:
                case ldn.JoinEvent():
                    p = event.participant
                    # Skip our own join event
                    if str(p.mac_address) == relay_mac:
                        logger.info(
                            "PRIMARY JOIN idx=%d (self, skipping relay)", event.index
                        )
                        continue
                    logger.info(
                        "PRIMARY JOIN idx=%d %s IP=%s MAC=%s",
                        event.index,
                        p.name.decode(errors="replace"),
                        p.ip_address,
                        p.mac_address,
                    )
                    await send_msg(peer_stream, make_join_msg(event.index, p))
                case ldn.LeaveEvent():
                    p = event.participant
                    logger.info(
                        "PRIMARY LEAVE idx=%d %s",
                        event.index,
                        p.name.decode(errors="replace"),
                    )
                    await send_msg(peer_stream, make_leave_msg(event.index))
                case ldn.ApplicationDataChanged():
                    logger.info("APP_DATA %d bytes", len(event.new))
                    await send_msg(peer_stream, AppDataMsg(data=event.new.hex()))
                case ldn.AcceptPolicyChanged():
                    logger.info("ACCEPT %d -> %d", event.old, event.new)
                    await send_msg(peer_stream, AcceptMsg(policy=event.new))
                case ldn.DisconnectEvent():
                    logger.info("DISCONNECT reason=%s", event.reason)
                    break
    except (trio.ClosedResourceError, trio.BrokenResourceError):
        pass


async def handle_secondary_events(
    network: ldn.APNetwork, peer_stream: trio.SocketStream
) -> None:
    """Secondary: monitor local APNetwork events and forward them to Primary.

    Notifies Primary when Switch B joins or leaves.
    """
    while True:
        event = await network.next_event()
        match event:
            case ldn.JoinEvent():
                p = event.participant
                logger.info(
                    "SECONDARY JOIN idx=%d %s IP=%s MAC=%s",
                    event.index,
                    p.name.decode(errors="replace"),
                    p.ip_address,
                    p.mac_address,
                )
                await send_msg(peer_stream, make_join_msg(event.index, p))
            case ldn.LeaveEvent():
                p = event.participant
                logger.info(
                    "SECONDARY LEAVE idx=%d %s",
                    event.index,
                    p.name.decode(errors="replace"),
                )
                await send_msg(peer_stream, make_leave_msg(event.index))


async def handle_peer_messages_primary(reader: LineReader) -> None:
    """Primary: process messages from Secondary.

    LEAVE is logged only (no automatic shutdown).
    Returns only on TCP disconnect, which triggers nursery cancellation.
    """
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            logger.info("Secondary disconnected")
            break
        except InvalidMessageError as e:
            logger.warning("%s", e)
            continue

        match msg:
            case LeaveMsg():
                logger.info("REMOTE LEAVE idx=%d (continuing relay)", msg.index)
            case JoinMsg():
                # Additional participants (future support)
                logger.info(
                    "REMOTE JOIN idx=%d IP=%s MAC=%s (additional participant, not yet supported)",
                    msg.index,
                    msg.ip,
                    msg.mac,
                )


async def handle_peer_messages_secondary(
    network: ldn.APNetwork, reader: LineReader
) -> None:
    """Secondary: process JOIN/LEAVE/APP_DATA/ACCEPT messages from Primary."""
    while True:
        try:
            msg = await recv_msg(reader)
        except (trio.ClosedResourceError, trio.EndOfChannel):
            logger.info("Primary disconnected")
            break
        except InvalidMessageError as e:
            logger.warning("%s", e)
            continue

        match msg:
            case JoinMsg():
                logger.info(
                    "REMOTE JOIN idx=%d IP=%s MAC=%s", msg.index, msg.ip, msg.mac
                )
                inject_virtual_participant(
                    network,
                    index=msg.index,
                    ip=msg.ip,
                    mac_str=msg.mac,
                    name=bytes.fromhex(msg.name),
                    app_version=msg.app_version,
                    platform=msg.platform,
                )
            case LeaveMsg():
                logger.info("REMOTE LEAVE idx=%d", msg.index)
                remove_virtual_participant(network, msg.index)
            case AppDataMsg():
                logger.info("APP_DATA updating (%d bytes)", len(msg.data) // 2)
                network.set_application_data(bytes.fromhex(msg.data))
            case AcceptMsg():
                logger.info("ACCEPT policy=%d", msg.policy)
                network.set_accept_policy(msg.policy)
            case ConnectedMsg():
                logger.info(
                    "CONNECTED Primary STA assigned: idx=%d IP=%s",
                    msg.index,
                    msg.ip,
                )
                # Verify that the IP matches Switch B's
                for idx, p in enumerate(network._network.participants):
                    if p.connected and idx > 0:
                        if p.ip_address != msg.ip:
                            logger.warning(
                                "IP mismatch: Switch B has %s, Primary expects %s",
                                p.ip_address,
                                msg.ip,
                            )
                        else:
                            logger.info("IP match: %s", p.ip_address)


# --- Packet trace (TRACE level) ---

_TRACE_INTERFACES = (
    IF_LDN,
    IF_LDN_MON,
    IF_LDN_TAP,
    IF_RELAY_STA,
    IF_RELAY_BR,
    IF_BRIDGE,
    IF_GRETAP,
)

ETH_P_ALL = 0x0003


def _format_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


async def _capture_packets(ifname: str) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((ifname, 0))
        sock.setblocking(False)
        while True:
            await trio.lowlevel.wait_readable(sock)
            data = sock.recv(65535)
            if len(data) < 14:
                continue
            dst = _format_mac(data[0:6])
            src = _format_mac(data[6:12])
            ethertype = struct.unpack("!H", data[12:14])[0]
            logger.log(
                TRACE,
                "%s %s > %s ethertype=0x%04x len=%d",
                ifname,
                src,
                dst,
                ethertype,
                len(data),
            )
    except OSError:
        pass
    finally:
        sock.close()


def _start_packet_trace(nursery: trio.Nursery, ipr: IPRoute) -> None:
    if not logger.isEnabledFor(TRACE):
        return
    for ifname in _TRACE_INTERFACES:
        if _ifindex(ipr, ifname) is not None:
            nursery.start_soon(_capture_packets, ifname)


# --- Main flows ---


async def run_primary(ipr: IPRoute, config: PrimaryConfig):
    # 1. Scan (no STA association; all info is obtained from the scan result)
    logger.info(
        "Scanning for LDN network (create a local-communication room on Switch A)"
    )
    info = await scan_ldn(config.keys, config.phy)
    if info is None:
        logger.error("LDN network not found")
        return

    host = info.participants[0]
    logger.info(
        "Found network: ch=%d proto=%d ver=%d app_ver=%d BSSID=%s host_ip=%s host_mac=%s",
        info.channel,
        info.protocol,
        info.version,
        info.app_version,
        info.address,
        host.ip_address,
        host.mac_address,
    )

    # 2. GRETAP tunnel + bridge
    logger.info("Setting up GRETAP tunnel + bridge")
    with setup_tunnel(ipr, config.local, config.remote) as (idx_gretap, idx_br):
        # 3. STA connect (complete the relay before Switch B joins)
        logger.info("Connecting to Switch A as %s", config.switch_b_mac)
        param = ldn.ConnectNetworkParam(
            keys=config.keys,
            phyname=config.phy,
            network=info,
            password=config.ldn_passphrase or b"",
            name=b"LDN-Tunnel",
            address=ldn.MACAddress(config.switch_b_mac),
        )

        max_connect_attempts = 3
        for attempt in range(max_connect_attempts):
            if attempt > 0:
                logger.info(
                    "Retry %d/%d in 2 seconds", attempt + 1, max_connect_attempts
                )
                await trio.sleep(2)
                logger.info("Re-scanning...")
                fresh_info = await scan_ldn(config.keys, config.phy)
                if fresh_info is None:
                    logger.warning("Network not found on re-scan")
                    continue
                info = fresh_info
                param.network = info

            try:
                async with ldn.connect(param) as sta:
                    sta_index = sta._participant_id
                    sta_ip = sta.participant().ip_address
                    logger.info(
                        "Connected: participant=%d IP=%s MAC=%s (spoofed)",
                        sta_index,
                        sta_ip,
                        config.switch_b_mac,
                    )

                    # 4. Relay setup (completed before Switch B joins)
                    logger.info("Setting up station relay")
                    with setup_station_relay(
                        ipr, idx_gretap, idx_br, sta.ifindex, IF_LDN
                    ):
                        # 5. Wait for Secondary
                        listeners = await trio.open_tcp_listeners(
                            config.control_port, host=config.local
                        )
                        try:
                            logger.info(
                                "Waiting for secondary on %s:%d",
                                config.local,
                                config.control_port,
                            )

                            peer_stream = await listeners[0].accept()
                            reader = LineReader(peer_stream)
                            logger.info("Secondary connected")

                            # 6. Send NETWORK + CONNECTED
                            net_msg = make_network_msg_from_scan(info)
                            await send_msg(peer_stream, net_msg)
                            await send_msg(
                                peer_stream,
                                ConnectedMsg(index=sta_index, ip=sta_ip),
                            )
                            logger.info("NETWORK + CONNECTED sent, waiting for READY")

                            while True:
                                try:
                                    ready_msg = await recv_msg(reader)
                                except (trio.ClosedResourceError, trio.EndOfChannel):
                                    logger.error("Secondary disconnected before READY")
                                    return
                                except InvalidMessageError as e:
                                    logger.warning("%s", e)
                                    continue
                                match ready_msg:
                                    case ReadyMsg():
                                        break
                                    case _:
                                        logger.warning(
                                            "Ignoring unexpected message: %r",
                                            ready_msg,
                                        )
                            logger.info("Secondary is ready")
                            logger.info(
                                "Join via local communication on Switch B (Ctrl+C to exit)"
                            )

                            # 7. Event loop
                            async with trio.open_nursery() as nursery:
                                _start_packet_trace(nursery, ipr)
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

                    # Event loop exited normally; no retry needed
                    break
            except ConnectionError as e:
                logger.error("Connect failed: %s", e)
                if attempt < max_connect_attempts - 1:
                    logger.info("Will retry...")
                    continue
                raise


async def run_secondary(ipr: IPRoute, config: SecondaryConfig):
    # 1. GRETAP + bridge
    logger.info("Setting up GRETAP tunnel + bridge")
    with setup_tunnel(ipr, config.local, config.remote) as (idx_gretap, idx_br):
        # 2. Connect to primary
        logger.info(
            "Connecting to primary at %s:%d", config.remote, config.control_port
        )
        peer_stream = await trio.open_tcp_stream(config.remote, config.control_port)
        reader = LineReader(peer_stream)
        logger.info("Connected to primary")

        # 3. Receive NETWORK
        while True:
            try:
                net_msg = await recv_msg(reader)
            except InvalidMessageError as e:
                logger.warning("%s", e)
                continue
            match net_msg:
                case NetworkMsg():
                    break
                case _:
                    logger.warning("Ignoring unexpected message: %r", net_msg)
        network_id = net_msg.network_id
        host_p = net_msg.participants[0]
        logger.info(
            "Received NETWORK: game_id=%#018x ch=%d network_id=%d host_ip=%s host_mac=%s",
            net_msg.local_communication_id,
            net_msg.channel,
            network_id,
            host_p.ip,
            host_p.mac,
        )

        # 4. Host proxy LDN
        logger.info("Hosting proxy LDN network")
        param = make_create_param(
            config.keys, config.phy, net_msg, config.ldn_passphrase or b""
        )

        async with ldn.create_network(param) as network:
            # 5. Patch: configure as Switch A proxy
            patch_secondary_network(ipr, network, net_msg, network.ifindex_tap)

            # 6. Bridge TAP
            add_tap_to_bridge(
                ipr, idx_gretap, idx_br, network.ifindex_tap, network.ifindex_monitor
            )

            # 7. Signal ready
            await send_msg(peer_stream, ReadyMsg())

            logger.info(
                "Ready: subnet=169.254.%d.0/24 participant_0=%s/%s (Ctrl+C to exit)",
                network_id,
                host_p.ip,
                host_p.mac,
            )

            async with trio.open_nursery() as nursery:
                _start_packet_trace(nursery, ipr)
                nursery.start_soon(handle_secondary_events, network, peer_stream)
                nursery.start_soon(handle_peer_messages_secondary, network, reader)


async def main():
    parser = argparse.ArgumentParser(description="LDN Tunnel Node v4")
    parser.add_argument("keys", help="Path to prod.keys")
    parser.add_argument(
        "--role",
        required=True,
        choices=["primary", "secondary"],
        help="primary: MAC-spoofed STA relay, secondary: AP proxy",
    )
    parser.add_argument("--local", required=True, help="Local WireGuard IP")
    parser.add_argument("--remote", required=True, help="Remote WireGuard IP")
    parser.add_argument("--phy", required=True, help="Wi-Fi phy name (e.g. phy1)")
    parser.add_argument(
        "--switch-b-mac",
        default=None,
        help="Switch B MAC address (e.g. 64:B5:C6:1B:14:9B)",
    )
    parser.add_argument(
        "--ldn-passphrase",
        default=None,
        help="Path to binary file containing the LDN passphrase (empty if omitted). "
        "See: https://github.com/kinnay/NintendoClients/wiki/LDN-Passphrases",
    )
    parser.add_argument(
        "--control-port",
        type=int,
        default=DEFAULT_CONTROL_PORT,
        help=f"Control port between Primary and Secondary (default: {DEFAULT_CONTROL_PORT})",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["trace", "debug", "info", "warning", "error", "critical"],
        help="Logging verbosity (default: info)",
    )
    args = parser.parse_args()

    level = (
        TRACE if args.log_level == "trace" else getattr(logging, args.log_level.upper())
    )
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if args.ldn_passphrase is not None:
        with open(args.ldn_passphrase, "rb") as f:
            passphrase = f.read()
    else:
        passphrase = None

    common = dict(
        keys=ldn.load_keys(args.keys),
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
