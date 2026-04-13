"""
Dynamic Host Blocking System - POX SDN Controller
Student: Krrish Singla | PES1UG24AM141
Course: UE24CS252B - Computer Networks

Place this file in: ~/pox/ext/dynamic_blocker.py

Run with:
    cd ~/pox
    python3 pox.py dynamic_blocker
"""

from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr
import datetime
import collections
import time

log = core.getLogger()

# ─── Tunable parameters ───────────────────────────────────────────
PACKET_THRESHOLD = 50    # packets per host allowed in TIME_WINDOW
TIME_WINDOW      = 10    # seconds
BLOCK_DURATION   = 60    # seconds before rule expires
LOG_FILE         = "/home/vboxuser/Desktop/CN Orange/blocking_events.log"
# ──────────────────────────────────────────────────────────────────


def write_log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    log.info(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        log.warning(f"Could not write log: {e}")


class DynamicHostBlocker(EventMixin):
    _eventMixin_events = set()

    def __init__(self):
        self.listenTo(core.openflow)

        # mac_to_port[dpid][mac] = port
        self.mac_to_port = {}

        # packet timestamps: counts[dpid][mac] = deque of timestamps
        self.counts = collections.defaultdict(
            lambda: collections.defaultdict(collections.deque)
        )

        # blocked[dpid] = set of blocked MAC strings
        self.blocked = collections.defaultdict(set)

        write_log("=" * 55)
        write_log("Dynamic Host Blocking System started (POX)")
        write_log(f"Threshold : {PACKET_THRESHOLD} pkts / {TIME_WINDOW}s")
        write_log(f"Block rule: hard_timeout = {BLOCK_DURATION}s")
        write_log("=" * 55)

    def _handle_ConnectionUp(self, event):
        """Called when a switch connects to the controller."""
        dpid = dpid_to_str(event.dpid)
        write_log(f"[SETUP] Switch connected: dpid={dpid}")
        self.mac_to_port[event.dpid] = {}

        # Install table-miss rule: send unknown packets to controller
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

    def _block_host(self, event, src_mac):
        """Install a high-priority DROP rule for src_mac."""
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.hard_timeout = BLOCK_DURATION
        msg.idle_timeout = 0
        msg.match.dl_src = EthAddr(src_mac)
        # No actions = DROP
        event.connection.send(msg)

        self.blocked[event.dpid].add(src_mac)
        write_log(f"[BLOCKED]  dpid={dpid_to_str(event.dpid)}  "
                  f"host={src_mac}  (expires in {BLOCK_DURATION}s)")

    def _handle_PacketIn(self, event):
        """Called when a packet arrives that has no matching flow rule."""
        packet     = event.parsed
        dpid       = event.dpid
        in_port    = event.port

        if not packet.parsed:
            return

        src = str(packet.src)
        dst = str(packet.dst)

        # ── Rate tracking ─────────────────────────────────────────
        now = time.time()
        dq  = self.counts[dpid][src]
        dq.append(now)

        # Remove timestamps outside the window
        while dq and now - dq[0] > TIME_WINDOW:
            dq.popleft()

        pkt_count = len(dq)

        # If already blocked, ignore
        if src in self.blocked[dpid]:
            return

        # Check threshold
        if pkt_count > PACKET_THRESHOLD:
            write_log(f"[ALERT]  dpid={dpid_to_str(dpid)}  host={src}  "
                      f"sent {pkt_count} pkts in {TIME_WINDOW}s — BLOCKING")
            self._block_host(event, src)
            return

        # ── Normal learning-switch behaviour ──────────────────────
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            # Install forward rule
            msg = of.ofp_flow_mod()
            msg.priority    = 1
            msg.idle_timeout = 30
            msg.match.dl_dst = EthAddr(dst)
            msg.match.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)

            # Send current packet
            msg2 = of.ofp_packet_out()
            msg2.data    = event.ofp
            msg2.in_port = in_port
            msg2.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg2)
        else:
            # Flood — destination unknown
            msg = of.ofp_packet_out()
            msg.data    = event.ofp
            msg.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)


def launch():
    core.registerNew(DynamicHostBlocker)
    write_log("Dynamic Host Blocking System loaded.")
