#!/usr/bin/env python3
"""
Mininet topology and configuration script for PyRouter lab.
Refactored for style consistency (PEP8), without changing function or variable names.
"""

import os
import sys
import argparse
import subprocess
from time import sleep, time

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNetConnections, quietRun, custom, irange
from mininet.cli import CLI


# Parse command-line arguments (none currently defined)
parser = argparse.ArgumentParser(
    description="Mininet portion of pyrouter"
)
args = parser.parse_args()
lg.setLogLevel('info')


class PyRouterTopo(Topo):
    """
    Topology:
        server1 \  
                router----client
        server2 /
    All links limited by bandwidth, delay, and loss.
    """

    def __init__(self, args):
        super(PyRouterTopo, self).__init__()

        nodeconfig = {'cpu': -1}
        self.addHost('server1', **nodeconfig)
        self.addHost('server2', **nodeconfig)
        self.addHost('router', **nodeconfig)
        self.addHost('client', **nodeconfig)

        linkconfig = {
            'bw': 10,
            'delay': 0.02,
            'loss': 0.0
        }

        for node in ['server1', 'server2', 'client']:
            self.addLink(node, 'router', **linkconfig)


def set_ip_pair(net, node1, node2, ip1, ip2):
    """
    Configure IP addresses on the two ends of a link between node1 and node2.
    """
    h1 = net.get(node1)
    h2 = net.get(node2)
    intf_pair = h1.connectionsTo(h2)[0]
    intf_pair[0].setIP(ip1)
    intf_pair[1].setIP(ip2)


def reset_macs(net, node, macbase):
    """
    Reset MAC addresses on all interfaces of a node, using macbase format.
    """
    host = net.get(node)
    for idx, intf in enumerate(host.intfList(), start=1):
        mac = macbase.format(idx)
        host.setMAC(mac, intf)
    # Print assigned MACs
    for intf in host.intfList():
        print(node, intf, host.MAC(intf))


def set_route(net, fromnode, prefix, gw):
    """
    Add a static route on fromnode for prefix via gateway gw.
    """
    node = net.get(fromnode)
    node.cmdPrint(f"route add -net {prefix} gw {gw}")


def setup_addressing(net):
    """
    Configure MACs, IPs, routing tables, and write forwarding_table.txt.
    """
    # Reset MAC addresses
    reset_macs(net, 'server1', '10:00:00:00:00:{:02x}')
    reset_macs(net, 'server2', '20:00:00:00:00:{:02x}')
    reset_macs(net, 'client',  '30:00:00:00:00:{:02x}')
    reset_macs(net, 'router',  '40:00:00:00:00:{:02x}')

    # Assign IP addresses
    set_ip_pair(net, 'server1', 'router', '192.168.100.1/30', '192.168.100.2/30')
    set_ip_pair(net, 'server2', 'router', '192.168.200.1/30', '192.168.200.2/30')
    set_ip_pair(net, 'client',  'router', '10.1.1.1/30',     '10.1.1.2/30')

    # Configure routes
    set_route(net, 'server1', '10.1.0.0/16',      '192.168.100.2')
    set_route(net, 'server1', '192.168.200.0/24', '192.168.100.2')
    set_route(net, 'server2', '10.1.0.0/16',      '192.168.200.2')
    set_route(net, 'server2', '192.168.100.0/24', '192.168.200.2')
    set_route(net, 'client',  '192.168.100.0/24', '10.1.1.2')
    set_route(net, 'client',  '192.168.200.0/24', '10.1.1.2')
    set_route(net, 'client',  '172.16.0.0/16',    '10.1.1.2')

    # Write forwarding table for router
    table = (
        "192.168.100.0 255.255.255.0 192.168.100.1 router-eth0\n"
        "192.168.200.0 255.255.255.0 192.168.200.1 router-eth1\n"
        "10.1.0.0      255.255.0.0   10.1.1.1    router-eth2\n"
    )
    with open('forwarding_table.txt', 'w') as fp:
        fp.write(table)


def disable_ipv6(net):
    """
    Disable IPv6 on all hosts in the network.
    """
    for host in net.values():
        host.cmdPrint('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        host.cmdPrint('sysctl -w net.ipv6.conf.default.disable_ipv6=1')


def main():
    """
    Build topology, configure addressing, disable IPv6, and start CLI.
    """
    topo = PyRouterTopo(args)
    net = Mininet(topo=topo, link=TCLink, cleanup=True, controller=None)
    setup_addressing(net)
    disable_ipv6(net)
    net.interact()


if __name__ == '__main__':
    main()
