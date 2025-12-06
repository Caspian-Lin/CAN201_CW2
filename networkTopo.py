from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.term import makeTerm


def initializeNetwork():
    """Initialize and configure the network topology"""
    # Create network instance with specific configurations
    network = Mininet(autoSetMacs=False, build=False, ipBase='10.0.1.0/24')
    return network


def configureControllers(network):
    """Add and configure remote controllers"""
    controller = network.addController('c1', RemoteController)
    return controller


def createHosts(network):
    """Create host nodes with specific configurations"""
    # Define hosts with custom settings
    client_host = network.addHost('client', cls=Host, defaultRoute=None)
    server_one = network.addHost('server_1', cls=Host, defaultRoute=None)
    server_two = network.addHost('server_2', cls=Host, defaultRoute=None)
    return client_host, server_one, server_two


def setupSwitch(network):
    """Create and configure SDN switch"""
    switch = network.addSwitch('s1', cls=OVSKernelSwitch, failMode='secure')
    return switch


def establishConnections(network, client, server1, server2, switch):
    """Establish network links between components"""
    network.addLink(client, switch)
    network.addLink(server1, switch)
    network.addLink(server2, switch)


def assignNetworkAddresses(client, server1, server2):
    """Configure IP addresses for host interfaces"""
    client.setIP(intf='client-eth0', ip='10.0.1.5/24')
    server1.setIP(intf='server_1-eth0', ip='10.0.1.2/24')
    server2.setIP(intf='server_2-eth0', ip='10.0.1.3/24')


def setMacAddresses(client, server1, server2):
    """Assign specific MAC addresses to host interfaces"""
    client.setMAC(intf="client-eth0", mac="00:00:00:00:00:03")
    server1.setMAC(intf="server_1-eth0", mac="00:00:00:00:00:01")
    server2.setMAC(intf="server_2-eth0", mac="00:00:00:00:00:02")


def launchTerminalSessions(network, client, server1, server2, switch, controller):
    """Launch terminal sessions for all network components"""
    network.terms += makeTerm(client)
    network.terms += makeTerm(server1)
    network.terms += makeTerm(server2)
    network.terms += makeTerm(switch)
    network.terms += makeTerm(controller)


def myTopo():
    # Initialize network infrastructure
    net = initializeNetwork()
    
    # Setup network components
    sdn_controller = configureControllers(net)
    client_node, server_one, server_two = createHosts(net)
    sdn_switch = setupSwitch(net)
    
    # Establish network connectivity
    establishConnections(net, client_node, server_one, server_two, sdn_switch)
    
    # Build network topology
    net.build()
    
    # Configure network addressing
    assignNetworkAddresses(client_node, server_one, server_two)
    setMacAddresses(client_node, server_one, server_two)
    
    # Activate network
    net.start()
    
    # Launch terminal interfaces
    launchTerminalSessions(net, client_node, server_one, server_two, sdn_switch, sdn_controller)
    
    # Enter interactive mode
    CLI(net)
    net.stop()


if __name__ == '__main__':
    myTopo()