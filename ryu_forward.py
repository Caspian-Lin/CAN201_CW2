#!/usr/bin/env python3
"""
ryu_forward.py
Author: Alex Chen (CS Senior, UCL)
Student ID: u1234567
Date: 2025-05-16

This is the basic Ryu controller for Task 4.1.
Implements an L2 learning switch with specific logic for TCP SYN packets.
Key points:
 - Uses idle_timeout=5 for TCP flows (as required).
 - Installs flows specifically for TCP connections upon seeing the SYN packet.
 - Handles ARP and ICMP with default learning/flooding.
 - Ignores LLDP packets.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types, arp


# Import in_proto for IPPROTO constants if needed, though not strictly necessary here
# from ryu.lib.packet import in_proto

class ryu_forward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ryu_forward, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss flow entry (priority=0).
        This sends all unmatched packets to the controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry: send to controller, no timeout
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_default(datapath, 0, match, actions)
        self.logger.info("Installed table-miss flow entry.")

    def add_flow_default(self, datapath, priority, match, actions):
        """
        Add a flow entry without idle timeout.
        Used for permanent rules like table-miss.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_specific(self, datapath, priority, match, actions):
        """
        Add a flow entry with idle_timeout=5.
        Used for learned flows like TCP connections.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=5)  # Required timeout
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle incoming packets and install appropriate flow entries.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        eth_src = eth.src
        eth_dst = eth.dst
        dpid = datapath.id

        # Learn MAC address to avoid FLOOD next time.
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port
        self.logger.info("Packet in: DPID=%s SRC_MAC=%s DST_MAC=%s IN_PORT=%s",
                         dpid, eth_src, eth_dst, in_port)

        # Determine output port
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow entry if destination is known (not flooding)
        # Only install flows for specific types when not flooding
        if out_port != ofproto.OFPP_FLOOD:
            # Match fields depend on the type of packet
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                # ARP packet: Match on Ethernet type and MACs
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        eth_dst=eth_dst, eth_src=eth_src)
                # ARP flows are typically short-lived or permanent, but spec says 5s for all non-table-miss
                self.add_flow_specific(datapath, 1, match, actions)

            elif eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    ip_src = ip_pkt.src
                    ip_dst = ip_pkt.dst
                    ip_proto = ip_pkt.proto

                    # ICMP packet: Match on IP proto ICMP
                    if ip_proto == 1:  # ICMP
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_src=ip_src, ipv4_dst=ip_dst,
                                                ip_proto=ip_proto)
                        self.add_flow_specific(datapath, 1, match, actions)

                    # TCP packet: Install flow only for new connections (SYN)
                    elif ip_proto == 6:  # TCP
                        tcp_pkt = pkt.get_protocol(tcp.tcp)
                        if tcp_pkt and (tcp_pkt.bits & tcp.TCP_SYN):
                            tcp_src_port = tcp_pkt.src_port
                            tcp_dst_port = tcp_pkt.dst_port
                            # Match on full 5-tuple for connection-specific flow
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=ip_src, ipv4_dst=ip_dst,
                                                    ip_proto=ip_proto,
                                                    tcp_src=tcp_src_port,
                                                    tcp_dst=tcp_dst_port)
                            self.add_flow_specific(datapath, 1, match, actions)
                            self.logger.info("Installed TCP flow for %s:%s -> %s:%s",
                                             ip_src, tcp_src_port, ip_dst, tcp_dst_port)

        # Construct and send Packet-Out message
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)