"""
Dynamic Host Blocking System - Automated Test Script
Student: Krrish Singla | PES1UG24AM141

Run this INSIDE the Mininet CLI using:
    mininet> py exec(open('/home/ubuntu/dynamic_host_blocking/test_scenarios.py').read())

Or run individual functions:
    mininet> py scenario1(net)
    mininet> py scenario2(net)
"""

import time
import subprocess


def scenario1(net):
    """
    SCENARIO 1 — Normal traffic (should NOT be blocked)
    ────────────────────────────────────────────────────
    h1 pings h2 normally. Packet rate is well below the threshold.
    Expected: all pings succeed, no blocking rule installed.
    """
    print("\n" + "="*60)
    print("SCENARIO 1: Normal Host Communication")
    print("="*60)
    h1 = net.get("h1")
    h2 = net.get("h2")

    print("\n[1] h1 pings h2 (5 packets) — should ALL succeed")
    result = h1.cmd("ping -c 5 10.0.0.2")
    print(result)

    print("\n[2] h2 pings h3 (5 packets) — should ALL succeed")
    h3 = net.get("h3")
    result = h2.cmd("ping -c 5 10.0.0.3")
    print(result)

    print("\n[3] iperf: h1 (server) <-> h2 (client) for 5 seconds")
    h1.cmd("iperf -s &")
    time.sleep(0.5)
    result = h2.cmd("iperf -c 10.0.0.1 -t 5")
    print(result)
    h1.cmd("kill %iperf")

    print("\n[4] Flow table after normal traffic:")
    print(subprocess.getoutput("sudo ovs-ofctl -O OpenFlow13 dump-flows s1"))
    print("\n>>> SCENARIO 1 COMPLETE — all traffic allowed as expected\n")


def scenario2(net):
    """
    SCENARIO 2 — Suspicious / flooding host (SHOULD be blocked)
    ────────────────────────────────────────────────────────────
    h4 floods h1 with rapid pings, exceeding the 50-packet / 10s threshold.
    Expected:
        • Ryu detects the flood → installs DROP rule for h4
        • h4 can no longer reach any host
        • h1, h2, h3 continue communicating normally
    """
    print("\n" + "="*60)
    print("SCENARIO 2: Suspicious Host Flooding → Auto-Block")
    print("="*60)

    h1 = net.get("h1")
    h4 = net.get("h4")

    print("\n[1] h4 pings h1 before flooding — should succeed")
    result = h4.cmd("ping -c 2 10.0.0.1")
    print(result)

    print("\n[2] h4 floods h1 (100 rapid pings) — controller should block h4")
    # -i 0.05 means one ping every 50ms → 100 pkts in ~5s >> threshold
    result = h4.cmd("ping -c 100 -i 0.05 10.0.0.1 2>&1 | tail -5")
    print(result)

    print("\n[3] Waiting 3s for DROP rule to propagate ...")
    time.sleep(3)

    print("\n[4] Flow table — look for DROP rule with eth_src=h4's MAC:")
    print(subprocess.getoutput("sudo ovs-ofctl -O OpenFlow13 dump-flows s1"))

    print("\n[5] h4 tries to ping h1 AFTER blocking — should FAIL (0 received)")
    result = h4.cmd("ping -c 4 10.0.0.1")
    print(result)

    print("\n[6] h4 tries to ping h2 AFTER blocking — should also FAIL")
    result = h4.cmd("ping -c 4 10.0.0.2")
    print(result)

    print("\n[7] h1 pings h2 (legitimate hosts still work) — should succeed")
    result = h1.cmd("ping -c 4 10.0.0.2")
    print(result)

    print("\n[8] Check blocking log:")
    try:
        with open("blocking_events.log") as f:
            print(f.read())
    except FileNotFoundError:
        print("(Log file not found — check Ryu terminal)")

    print("\n>>> SCENARIO 2 COMPLETE — h4 blocked, others unaffected\n")


def check_flow_table():
    """Quick helper to dump the flow table at any time."""
    print(subprocess.getoutput("sudo ovs-ofctl -O OpenFlow13 dump-flows s1"))


def latency_test(net):
    """Measure and report RTT latency between h1 and h2."""
    print("\n=== Latency Test: h1 → h2 (20 pings) ===")
    h1 = net.get("h1")
    result = h1.cmd("ping -c 20 10.0.0.2")
    # Extract the rtt line
    for line in result.splitlines():
        if "rtt" in line or "round-trip" in line:
            print("Result:", line)
    print(result)


def throughput_test(net):
    """Measure TCP throughput between h1 (server) and h3 (client) using iperf."""
    print("\n=== Throughput Test: h1 (server) ↔ h3 (client) — 10 seconds ===")
    h1 = net.get("h1")
    h3 = net.get("h3")
    h1.cmd("iperf -s &")
    time.sleep(1)
    result = h3.cmd("iperf -c 10.0.0.1 -t 10")
    print(result)
    h1.cmd("kill %iperf")
