#!/usr/bin/env python3
"""
ryu_forward.py - CAN201 Part II
Implements:
  - Task 2: Full ping connectivity (ICMP + ARP)
  - Task 4.1: Forward Client(10.0.1.5) -> Server1(10.0.1.2) TCP SYN normally
All non-table-miss flows have idle_timeout=5.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, icmp

class ForwardController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ForwardController, self).__init__(*args, **kwargs)
        # IMPORTANT: Must match the port assignment from networkTopo.py!
        # We observed: client=1, server1=2, server2=3
        self.ip_to_port = {
            '10.0.1.5': 1,   # client
            '10.0.1.2': 2,   # server1
            '10.0.1.3': 3    # server2
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def install_table_miss(self, ev):
        """Install table-miss flow to send unknown packets to controller."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        """Helper to install flow entries with optional timeout."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    def handle_arp_flood(self, datapath, in_port, data):
        """Simple: just flood ARP requests (hosts will reply)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        # Parse upper-layer protocols
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # Handle ARP by flooding (simple but works in this small topo)
        if arp_pkt:
            self.handle_arp_flood(datapath, in_port, msg.data)
            return

        # Handle ICMP (ping)
        if icmp_pkt and ipv4_pkt:
            dst_ip = ipv4_pkt.dst
            if dst_ip in self.ip_to_port:
                out_port = self.ip_to_port[dst_ip]
                match = parser.OFPMatch(
                    eth_type=0x0800,    # IPv4
                    ip_proto=1,         # ICMP
                    ipv4_src=ipv4_pkt.src,
                    ipv4_dst=dst_ip
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 100, match, actions, idle_timeout=5)
                # Send the current packet
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
            return

        # Task 4.1: Handle TCP SYN from Client to Server1
        if tcp_pkt and ipv4_pkt:
            if (ipv4_pkt.src == '10.0.1.5' and
                ipv4_pkt.dst == '10.0.1.2' and
                tcp_pkt.has_flags(tcp.TCP_SYN) and
                not tcp_pkt.has_flags(tcp.TCP_ACK)):

                self.logger.info(">>> FORWARD: Client->Server1 TCP SYN detected")

                match = parser.OFPMatch(
                    eth_type=0x0800,    # IPv4
                    ip_proto=6,         # TCP
                    ipv4_src='10.0.1.5/24',
                    ipv4_dst='10.0.1.2/24'
                )
                out_port = self.ip_to_port['10.0.1.2']  # port 2
                actions = [parser.OFPActionOutput(out_port)]

                # Install flow with 5s idle timeout
                self.add_flow(datapath, 200, match, actions, idle_timeout=5)

                # Send original packet out
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
                return

        # Default: flood unknown traffic (should rarely happen)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)