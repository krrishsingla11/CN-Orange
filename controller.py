"""
Dynamic Host Blocking System - Ryu SDN Controller
Student: Krrish Singla | PES1UG24AM141
Course: UE24CS252B - Computer Networks

Description:
    Monitors traffic per host. If a host exceeds a packet-rate threshold
    within a time window, it is automatically blocked by installing a
    high-priority DROP flow rule. All events are logged to a file.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub

import datetime
import collections
import os

# ─── Tunable parameters ──────────────────────────────────────────────────────
PACKET_THRESHOLD = 50       # packets per host allowed in one time window
TIME_WINDOW      = 10       # seconds for the sliding window
BLOCK_DURATION   = 60       # seconds a flow rule stays (hard_timeout)
LOG_FILE         = "blocking_events.log"
# ─────────────────────────────────────────────────────────────────────────────


def log(msg: str):
    """Write a timestamped message to both stdout and the log file."""
    ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


class DynamicHostBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # mac_to_port[dpid][mac] = port
        self.mac_to_port = {}

        # packet counter: counts[dpid][src_mac] = deque of timestamps
        self.counts = collections.defaultdict(
            lambda: collections.defaultdict(collections.deque)
        )

        # blocked[dpid] = set of blocked MAC addresses
        self.blocked = collections.defaultdict(set)

        log("=" * 60)
        log("Dynamic Host Blocking System started")
        log(f"Threshold : {PACKET_THRESHOLD} pkts / {TIME_WINDOW}s window")
        log(f"Block rule: hard_timeout = {BLOCK_DURATION}s")
        log("=" * 60)

        # Background thread cleans up expired counters
        self.monitor_thread = hub.spawn(self._monitor)

    # ── OpenFlow helpers ──────────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, hard_timeout=hard_timeout,
            idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _block_host(self, datapath, src_mac: str):
        """Install a high-priority DROP rule for src_mac."""
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch(eth_src=src_mac)
        self._add_flow(datapath, priority=100, match=match,
                       actions=[],              # empty = DROP
                       hard_timeout=BLOCK_DURATION)
        self.blocked[datapath.id].add(src_mac)
        log(f"[BLOCKED]  dpid={datapath.id}  host={src_mac}  "
            f"(rule expires in {BLOCK_DURATION}s)")

    # ── Background monitor ────────────────────────────────────────────────────

    def _monitor(self):
        """Every second, expire old timestamps and unblock hosts whose rules
        have timed out (Ryu does NOT get a callback when hard_timeout fires,
        so we manage the unblock list ourselves)."""
        unblock_at = {}   # (dpid, mac) -> unblock timestamp

        while True:
            hub.sleep(1)
            now = datetime.datetime.now().timestamp()

            # Prune timestamps older than TIME_WINDOW
            for dpid, host_map in self.counts.items():
                for mac, dq in list(host_map.items()):
                    while dq and now - dq[0] > TIME_WINDOW:
                        dq.popleft()

            # Track when blocked hosts should be unblocked
            for dpid, macs in list(self.blocked.items()):
                for mac in list(macs):
                    key = (dpid, mac)
                    if key not in unblock_at:
                        unblock_at[key] = now + BLOCK_DURATION
                    elif now >= unblock_at[key]:
                        self.blocked[dpid].discard(mac)
                        del unblock_at[key]
                        log(f"[UNBLOCKED] dpid={dpid}  host={mac}  "
                            f"(rule expired)")

    # ── Switch feature handshake ──────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Default table-miss rule: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        log(f"[SETUP]    Switch connected: dpid={datapath.id}")

    # ── Packet-in handler ─────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        dpid     = datapath.id
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        src = eth_pkt.src
        dst = eth_pkt.dst

        # ── Suspicious-host check ─────────────────────────────────────────
        now = datetime.datetime.now().timestamp()
        dq  = self.counts[dpid][src]
        dq.append(now)
        # Prune old entries outside the window
        while dq and now - dq[0] > TIME_WINDOW:
            dq.popleft()

        pkt_count = len(dq)

        # If already blocked, drop silently (rule should handle it, but
        # packet_in may still fire briefly until the rule propagates)
        if src in self.blocked[dpid]:
            return

        if pkt_count > PACKET_THRESHOLD:
            log(f"[ALERT]    dpid={dpid}  host={src}  "
                f"sent {pkt_count} pkts in {TIME_WINDOW}s — BLOCKING")
            self._block_host(datapath, src)
            return

        # ── Normal learning-switch behaviour ──────────────────────────────
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # Install a forward rule so future packets bypass the controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self._add_flow(datapath, priority=1, match=match,
                           actions=actions, idle_timeout=30)

        # Send the current packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
