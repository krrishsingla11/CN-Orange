"""
Dynamic Host Blocking System - Mininet Topology
Student: Krrish Singla | PES1UG24AM141
Course: UE24CS252B - Computer Networks

Topology:
                   [Ryu Controller]
                         |
                        s1
                   /  |  |  \
                 h1   h2  h3  h4

    h1 - normal host
    h2 - normal host
    h3 - normal host
    h4 - attacker (used in test scenario 2 to trigger blocking)

Usage:
    sudo python3 topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log  import setLogLevel, info
from mininet.cli  import CLI
from mininet.link import TCLink
import time


class BlockingTopo(Topo):
    """Single switch connected to 4 hosts."""

    def build(self):
        # Add switch
        s1 = self.addSwitch("s1", protocols="OpenFlow10")

        # Add hosts
        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        h4 = self.addHost("h4", ip="10.0.0.4/24")   # attacker in scenario 2

        # Add links (100 Mbps, 5 ms delay)
        for host in [h1, h2, h3, h4]:
            self.addLink(host, s1, bw=100, delay="5ms", cls=TCLink)


def run():
    setLogLevel("info")

    topo = BlockingTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=None,   # we attach RemoteController below
        link=TCLink,
        autoSetMacs=True,
    )

    # Connect to the Ryu controller (must be running before this script)
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    net.start()
    info("\n*** Topology started\n")
    info("    h1 10.0.0.1  |  h2 10.0.0.2  |  h3 10.0.0.3  |  h4 10.0.0.4 (attacker)\n\n")

    # Give switches a moment to connect to the controller
    time.sleep(2)

    info("*** Running initial connectivity test (pingall) ...\n")
    net.pingAll()

    info("\n*** Opening Mininet CLI — type 'exit' when done\n")
    CLI(net)

    net.stop()


if __name__ == "__main__":
    run()
