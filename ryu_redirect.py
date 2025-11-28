#!/usr/bin/env python3
"""
ryu_redirect.py - CAN201 Part II
Implements:
  - Task 2: Full ping connectivity
  - Task 5.1: REDIRECT Client(10.0.1.5) -> Server1(10.0.1.2) TCP SYN to Server2(10.0.1.3)
CRITICAL FIX: Do NOT spoof source MAC! Only change dst IP and dst MAC.
This ensures the return path (Server2 -> Client) works correctly.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, icmp

class RedirectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RedirectController, self).__init__(*args, **kwargs)
        # Port mapping (MUST match networkTopo.py output!)
        self.ip_to_port = {
            '10.0.1.5': 1,   # client
            '10.0.1.2': 2,   # server1 (original target)
            '10.0.1.3': 3    # server2 (redirect target)
        }
        # Predefined MACs (from networkTopo.py)
        self.ip_to_mac = {
            '10.0.1.5': '00:00:00:00:01:05',
            '10.0.1.2': '00:00:00:00:01:02',
            '10.0.1.3': '00:00:00:00:01:03'
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def install_table_miss(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
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
        """Same as forward: just flood ARP."""
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

        if eth.ethertype == 0x88cc:  # LLDP
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if arp_pkt:
            self.handle_arp_flood(datapath, in_port, msg.data)
            return

        # Handle ICMP (same as forward controller)
        if icmp_pkt and ipv4_pkt:
            dst_ip = ipv4_pkt.dst
            if dst_ip in self.ip_to_port:
                out_port = self.ip_to_port[dst_ip]
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=1,
                    ipv4_src=ipv4_pkt.src,
                    ipv4_dst=dst_ip
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 100, match, actions, idle_timeout=5)
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
            return

        # Task 5.1: REDIRECT Client->Server1 TCP SYN to Server2
        if tcp_pkt and ipv4_pkt:
            if (ipv4_pkt.src == '10.0.1.5' and
                ipv4_pkt.dst == '10.0.1.2' and
                tcp_pkt.has_flags(tcp.TCP_SYN) and
                not tcp_pkt.has_flags(tcp.TCP_ACK)):

                self.logger.info(">>> REDIRECT: Client->Server1 SYN => Server2")

                # MATCH: original traffic (Client -> Server1)
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=6,
                    ipv4_src='10.0.1.5/24',
                    ipv4_dst='10.0.1.2/24'
                )

                # ACTION: change dst IP to Server2, dst MAC to Server2's MAC
                # DO NOT change src MAC! Let the switch handle L2 forwarding naturally.
                new_dst_ip = '10.0.1.3'
                new_dst_mac = self.ip_to_mac[new_dst_ip]
                out_port = self.ip_to_port[new_dst_ip]  # port 3

                actions = [
                    parser.OFPActionSetField(ipv4_dst=new_dst_ip),
                    parser.OFPActionSetField(eth_dst=new_dst_mac),
                    parser.OFPActionOutput(out_port)
                ]

                # Install redirect flow (5s timeout)
                self.add_flow(datapath, 200, match, actions, idle_timeout=5)

                # Send the current packet with modifications
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data  # original packet; switch will modify fields
                )
                datapath.send_msg(out)
                return

        # Flood anything else (should not happen in this closed topo)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)