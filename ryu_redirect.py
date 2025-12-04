#!/usr/bin/env python3
"""
ryu_redirect.py
Author: Alex Chen (CS Senior, UCL)
Student ID: u1234567
Date: 2025-12-04

This controller implements TCP flow redirection.
Redirects ALL TCP traffic destined for Server1 (10.0.1.2) to Server2 (10.0.1.3).
Handles bidirectional traffic correctly.
Uses idle_timeout=5 for all flows.

Key Fix:
1. 在反向流表项中，使用 `OFPActionSetField` 修改 SYN-ACK 包的源 MAC 和源 IP，使其看起来像来自 Server1。
2. 确保反向流表项优先级足够高。
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types

# Hardcoded network information
CLIENT_IP = '10.0.1.5'
CLIENT_MAC = '00:00:00:00:00:03'
SERVER1_IP = '10.0.1.2'
SERVER1_MAC = '00:00:00:00:00:01'
SERVER2_IP = '10.0.1.3'
SERVER2_MAC = '00:00:00:00:00:02'

class ryu_redirect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ryu_redirect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        print("[INFO] ryu_redirect controller initialized. Redirecting traffic from Server1 to Server2!")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss flow entry (priority=0).
        This sends all unmatched packets to the controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_default(datapath, 0, match, actions)
        print("[✓] Installed table-miss flow entry.")

    def add_flow_default(self, datapath, priority, match, actions):
        """Add a flow entry without idle timeout."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_specific(self, datapath, priority, match, actions):
        """Add a flow entry with idle_timeout=5."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=5)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle incoming packets and implement redirection logic.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        eth_src = eth.src
        eth_dst = eth.dst
        dpid = datapath.id

        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port

        # Process only IPv4 TCP packets for redirection
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt and ip_pkt.proto == 6:  # TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    ip_src = ip_pkt.src
                    ip_dst = ip_pkt.dst
                    tcp_src_port = tcp_pkt.src_port
                    tcp_dst_port = tcp_pkt.dst_port

                    # --- REDIRECTION LOGIC ---
                    # Case 1: Client -> Server1 (Redirect to Server2)
                    if ip_dst == SERVER1_IP and eth_dst == SERVER1_MAC:
                        print(f"[REDIRECT] Client ({ip_src}) -> Server1 ({ip_dst}): Redirecting to Server2")

                        # Step 1: 查找 Server2 的端口
                        server2_port = self.mac_to_port[dpid].get(SERVER2_MAC, None)
                        if server2_port is None:
                            print(f" [ERROR] Server2 MAC {SERVER2_MAC} not learned. Cannot redirect.")
                            return

                        print(f" [INFO] Found Server2 port: {server2_port}")

                        # Step 2: 构建动作列表：修改目的 MAC 和 IP，然后输出到 Server2 的端口
                        actions = [
                            parser.OFPActionSetField(eth_dst=SERVER2_MAC),
                            parser.OFPActionSetField(ipv4_dst=SERVER2_IP),
                            parser.OFPActionOutput(port=server2_port)
                        ]

                        # Step 3: 发送 PacketOut 消息，立即转发修改后的数据包
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)

                        # Step 4: 安装正向流表项 (Client -> Server2)
                        match_client_to_server2 = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_src, ipv4_dst=SERVER1_IP,  # 匹配原始目标
                            ip_proto=6, tcp_src=tcp_src_port, tcp_dst=tcp_dst_port
                        )
                        self.add_flow_specific(datapath, 2, match_client_to_server2, actions)
                        print(f" [REVERSE] Installed flow for Client -> Server2")

                        # Step 5: 安装反向流表项 (Server2 -> Client)
                        # 关键点：必须修改源 MAC 和源 IP，使其看起来像来自 Server1
                        match_server2_to_client = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=SERVER2_IP, ipv4_dst=ip_src,  # 匹配改写后的源
                            ip_proto=6, tcp_src=tcp_dst_port, tcp_dst=tcp_src_port
                        )
                        reverse_actions = [
                            parser.OFPActionSetField(eth_src=SERVER1_MAC),  # 修改源 MAC 为 Server1
                            parser.OFPActionSetField(ipv4_src=SERVER1_IP),  # 修改源 IP 为 Server1
                            parser.OFPActionSetField(eth_dst=CLIENT_MAC),  # 修改目的 MAC 为 Client
                            parser.OFPActionSetField(ipv4_dst=CLIENT_IP),  # 修改目的 IP 为 Client
                            parser.OFPActionOutput(port=self.mac_to_port[dpid].get(CLIENT_MAC, ofproto.OFPP_FLOOD))
                        ]
                        self.add_flow_specific(datapath, 3, match_server2_to_client, reverse_actions)
                        print(f" [REVERSE] Installed flow for Server2 -> Client")
                        return  # 已处理，不再继续

                    # Case 2: Client -> Server2 (No redirect needed)
                    elif ip_dst == SERVER2_IP and eth_dst == SERVER2_MAC:
                        print(f"[NORMAL] Client ({ip_src}) -> Server2 ({ip_dst}): No redirect needed")
                        # 安装正常流表项
                        match_normal = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_src, ipv4_dst=ip_dst,
                            ip_proto=6, tcp_src=tcp_src_port, tcp_dst=tcp_dst_port
                        )
                        out_port = self.mac_to_port[dpid].get(eth_dst, ofproto.OFPP_FLOOD)
                        actions = [parser.OFPActionOutput(port=out_port)]
                        self.add_flow_specific(datapath, 1, match_normal, actions)
                        # 发送数据包
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        return

        # --- DEFAULT LEARNING/FLOODING FOR OTHER PACKETS ---
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match_l2 = parser.OFPMatch(eth_dst=eth_dst)
            self.add_flow_specific(datapath, 1, match_l2, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)