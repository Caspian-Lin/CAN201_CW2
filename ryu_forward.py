from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, in_proto, tcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class ForwardingController(app_manager.RyuApp):
    """OpenFlow 1.3 based forwarding controller with MAC learning"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ForwardingController, self).__init__(*args, **kwargs)
        self.switch_mac_table = {}
        self.FLOW_IDLE_TIMEOUT = 5
        self.DEFAULT_PRIORITY = 0
        self.SPECIFIC_PRIORITY = 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_connection(self, ev):
        """Initialize switch with default table-miss flow entry"""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        empty_match = parser.OFPMatch()
        forward_to_controller = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER,
            ofp.OFPCML_NO_BUFFER
        )]
        self._install_permanent_flow(dp, self.DEFAULT_PRIORITY, empty_match, forward_to_controller)

    def _install_permanent_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install flow entry without timeout"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions
            )
        else:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions
            )
        datapath.send_msg(flow_mod)

    def _install_temporary_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install flow entry with idle timeout"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
                idle_timeout=self.FLOW_IDLE_TIMEOUT
            )
        else:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                idle_timeout=self.FLOW_IDLE_TIMEOUT
            )
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        """Process incoming packets and manage forwarding logic"""
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        eth_frame = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth_frame.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        src_mac = eth_frame.src
        dst_mac = eth_frame.dst
        switch_id = dp.id
        
        self.switch_mac_table.setdefault(switch_id, {})
        self.switch_mac_table[switch_id][src_mac] = in_port
        
        self.logger.info(f"\n{'='*50}\nPacket In Event\nSwitch: {switch_id}\n"
                        f"Source: {src_mac} @ port {in_port}\nDestination: {dst_mac}\n{'='*50}")
        
        out_port = self._determine_output_port(switch_id, dst_mac, ofp)
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofp.OFPP_FLOOD:
            match_criteria = self._create_match_criteria(eth_frame, pkt, in_port, parser)
            if match_criteria:
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self._install_temporary_flow(dp, self.SPECIFIC_PRIORITY, match_criteria, actions, msg.buffer_id)
                    return
                else:
                    self._install_temporary_flow(dp, self.SPECIFIC_PRIORITY, match_criteria, actions)
        
        packet_data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            packet_data = msg.data
        
        packet_out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=packet_data
        )
        dp.send_msg(packet_out)
        
        self.logger.info(f"Packet Out: {dst_mac} -> port {out_port}\n")

    def _determine_output_port(self, switch_id, dst_mac, ofproto):
        """Lookup destination port or flood if unknown"""
        if dst_mac in self.switch_mac_table[switch_id]:
            return self.switch_mac_table[switch_id][dst_mac]
        return ofproto.OFPP_FLOOD

    def _create_match_criteria(self, eth_frame, pkt, in_port, parser):
        """Generate OpenFlow match based on packet type"""
        match = None
        
        if eth_frame.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info(f"Installing ARP flow: {eth_frame.src} -> {eth_frame.dst}")
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                in_port=in_port,
                eth_dst=eth_frame.dst,
                eth_src=eth_frame.src
            )
        
        elif eth_frame.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto
            
            if protocol == in_proto.IPPROTO_ICMP:
                self.logger.info(f"Installing ICMP flow: {src_ip} -> {dst_ip}")
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=protocol,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    in_port=in_port
                )
            
            elif protocol == in_proto.IPPROTO_TCP:
                tcp_segment = pkt.get_protocol(tcp.tcp)
                src_port = tcp_segment.src_port
                dst_port = tcp_segment.dst_port
                
                self.logger.info(f"Installing TCP flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=protocol,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    tcp_src=src_port,
                    tcp_dst=dst_port
                )
        
        return match