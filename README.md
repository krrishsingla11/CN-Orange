# Dynamic Host Blocking System
**Student:** Krrish Singla | PES1UG24AM141  
**Course:** UE24CS252B – Computer Networks, PES University  
**Project #:** 18  

---

## Problem Statement

In traditional networks, blocking a misbehaving host requires manual administrator intervention — by which time significant damage (DoS, flooding, scanning) may already have occurred.

This project implements a **Dynamic Host Blocking System** using SDN principles. A Ryu OpenFlow controller continuously monitors per-host packet rates. When a host exceeds a configurable threshold (default: 50 packets in 10 seconds), the controller **automatically installs a high-priority DROP flow rule** on the switch, instantly blocking that host. All events are logged with timestamps. Blocked hosts are automatically unblocked after a configurable timeout.

---

## Architecture

```
 ┌─────────────────────────────────────────────────────┐
 │                  Ryu Controller                      │
 │  • Handles packet_in events                          │
 │  • Tracks per-host packet counts (sliding window)    │
 │  • Installs DROP rules on threshold breach           │
 │  • Logs all block/unblock events                     │
 └──────────────────┬──────────────────────────────────┘
                    │ OpenFlow 1.3
                    │
              ┌─────┴─────┐
              │    s1      │  OVS Switch
              └──┬──┬──┬──┘
                 │  │  │  │
                h1 h2 h3 h4
           10.0.0.1 .2 .3 .4
                            └── Simulated attacker
```

---

## File Structure

```
dynamic_host_blocking/
├── controller.py       # Ryu SDN controller (main logic)
├── topology.py         # Mininet topology (4 hosts, 1 switch)
├── test_scenarios.py   # Automated test helpers
└── README.md
```

---

## Setup & Execution

### Prerequisites

- Ubuntu 20.04 / 22.04 VM
- Mininet installed
- Ryu framework installed

### Install Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install mininet -y
pip3 install ryu --break-system-packages
```

### Step 1 — Start the Ryu Controller

Open **Terminal 1**:

```bash
ryu-manager controller.py
```

You should see:
```
[HH:MM:SS] Dynamic Host Blocking System started
[HH:MM:SS] Threshold : 50 pkts / 10s window
[HH:MM:SS] Block rule: hard_timeout = 60s
```

### Step 2 — Start the Mininet Topology

Open **Terminal 2**:

```bash
sudo python3 topology.py
```

This creates 1 switch + 4 hosts and opens the Mininet CLI.

### Step 3 — Run Test Scenarios

Inside the Mininet CLI:

```
mininet> py exec(open('test_scenarios.py').read())
mininet> py scenario1(net)
mininet> py scenario2(net)
```

---

## Test Scenarios

### Scenario 1 — Normal Traffic (NOT Blocked)

- h1 pings h2 (5 packets) → **all succeed**
- h2 pings h3 (5 packets) → **all succeed**
- iperf between h1 and h2 → **normal throughput**
- Flow table shows forwarding rules only, **no DROP rules**

### Scenario 2 — Suspicious Flooding Host (AUTO-BLOCKED)

- h4 sends 100 rapid pings to h1 (exceeds 50 pkts/10s threshold)
- Controller detects the anomaly → **installs DROP rule for h4**
- h4 tries to ping h1 after block → **0% received (blocked)**
- h4 tries to ping h2 → **also blocked**
- h1 pings h2 → **still works** (only h4 is affected)

---

## Expected Output

### Controller terminal (after h4 floods):
```
[2025-01-01 10:00:05] [ALERT]    dpid=1  host=xx:xx:xx:xx:xx:xx  sent 55 pkts in 10s — BLOCKING
[2025-01-01 10:00:05] [BLOCKED]  dpid=1  host=xx:xx:xx:xx:xx:xx  (rule expires in 60s)
```

### Flow table after blocking (ovs-ofctl dump-flows s1):
```
priority=100,eth_src=<h4_mac> actions=drop
priority=1,in_port=1,dl_dst=<h2_mac> actions=output:2
...
priority=0 actions=CONTROLLER:65535
```

### Ping from h4 after blocking:
```
PING 10.0.0.1: 100% packet loss
```

---

## Performance Metrics

| Metric | Tool | Normal | After Block |
|---|---|---|---|
| Latency (h1→h2) | ping | ~5ms | ~5ms (unaffected) |
| Throughput (h1↔h3) | iperf | ~90 Mbps | ~90 Mbps (unaffected) |
| h4 → h1 reachability | ping | 0% loss | 100% loss |
| Flow table entries | ovs-ofctl | forward rules | + DROP rule for h4 |

---

## Configuration

Edit the top of `controller.py` to tune behaviour:

```python
PACKET_THRESHOLD = 50    # packets per host in TIME_WINDOW seconds
TIME_WINDOW      = 10    # seconds
BLOCK_DURATION   = 60    # seconds before auto-unblock
```

---

## Cleanup

```bash
sudo mn -c
```

---

## References

1. Ryu SDN Framework — https://ryu.readthedocs.io/
2. OpenFlow 1.3 Specification — https://opennetworking.org/
3. Mininet Overview — https://mininet.org/overview/
4. Mininet Walkthrough — https://mininet.org/walkthrough/
5. Open vSwitch — https://www.openvswitch.org/
