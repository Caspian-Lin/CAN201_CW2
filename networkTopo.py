#!/usr/bin/env python3
"""
CAN201 - Part II: SDN Topology Setup
Author: [Your Team Name]
Purpose: Build the exact topology shown in Fig.1 of the spec.
         Client (10.0.1.5) <-> Switch <-> Server1 (10.0.1.2), Server2 (10.0.1.3)
         All connected to a remote Ryu controller (assumed on localhost:6653).
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def build_topology():
    # Create network with remote controller (Ryu)
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    info('*** Adding Ryu controller (127.0.0.1:6653)\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding hosts with fixed IPs and MACs (as per Fig.1)\n')
    client   = net.addHost('client',   ip='10.0.1.5/24',  mac='00:00:00:00:01:05')
    server1  = net.addHost('server1',  ip='10.0.1.2/24',  mac='00:00:00:00:01:02')
    server2  = net.addHost('server2',  ip='10.0.1.3/24',  mac='00:00:00:00:01:03')

    info('*** Adding Open vSwitch\n')
    s1 = net.addSwitch('s1')

    info('*** Connecting all hosts to the switch\n')
    net.addLink(client,  s1)
    net.addLink(server1, s1)
    net.addLink(server2, s1)

    info('*** Starting network\n')
    net.start()

    # Show actual port mapping (critical for Ryu controller!)
    info('\n*** IMPORTANT: Switch port assignment (by connection order)\n')
    info('    client   -> port %d\n' % s1.ports[client.intf()])
    info('    server1  -> port %d\n' % s1.ports[server1.intf()])
    info('    server2  -> port %d\n' % s1.ports[server2.intf()])
    info('    => We assume: client=1, server1=2, server2=3\n\n')

    info('*** Testing basic connectivity (should work after Ryu installs rules)\n')
    net.pingAll()

    info('*** Entering Mininet CLI. Run client.py / server.py here.\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')  # Show startup messages
    build_topology()