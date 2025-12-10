from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, in_proto, tcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class NetworkEndpoint:
    """Represents a network endpoint with IP and MAC"""
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac


class RedirectController(app_manager.RyuApp):
    """SDN controller implementing intelligent traffic redirection"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RedirectController, self).__init__(*args, **kwargs)
        self.forwarding_table = {}
        self.timeout_duration = 5
        
        self.endpoints = {
            'client': NetworkEndpoint('10.0.1.5', '00:00:00:00:00:03'),
            'server_primary': NetworkEndpoint('10.0.1.2', '00:00:00:00:00:01'),
            'server_backup': NetworkEndpoint('10.0.1.3', '00:00:00:00:00:02')
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def initialize_switch(self, ev):
        """Configure switch with default forwarding rule"""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        default_match = parser.OFPMatch()
        controller_action = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER,
            ofp.OFPCML_NO_BUFFER
        )]
        self._add_static_flow(dp, 0, default_match, controller_action)

    def _add_static_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add permanent flow entry to switch"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        flow_params = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': instructions
        }
        if buffer_id:
            flow_params['buffer_id'] = buffer_id
        
        flow_mod = parser.OFPFlowMod(**flow_params)
        datapath.send_msg(flow_mod)

    def _add_dynamic_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add temporary flow entry with idle timeout"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        flow_params = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': instructions,
            'idle_timeout': self.timeout_duration
        }
        if buffer_id:
            flow_params['buffer_id'] = buffer_id
        
        flow_mod = parser.OFPFlowMod(**flow_params)
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def process_packet(self, ev):
        """Main packet processing logic with redirection"""
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        src_mac = eth.src
        dst_mac = eth.dst
        switch_id = dp.id
        
        self.forwarding_table.setdefault(switch_id, {})
        self.forwarding_table[switch_id][src_mac] = in_port
        
        self._log_packet_arrival(switch_id, src_mac, dst_mac, in_port)
        
        out_port = self._lookup_port(switch_id, dst_mac, ofp)
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofp.OFPP_FLOOD:
            flow_match = self._build_match_rule(eth, pkt, in_port, parser, dp, ofp)
            if flow_match:
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self._add_dynamic_flow(dp, 1, flow_match['match'], flow_match['actions'], msg.buffer_id)
                    self._log_packet_departure(flow_match['final_dst'], flow_match['final_port'])
                    return
                else:
                    self._add_dynamic_flow(dp, 1, flow_match['match'], flow_match['actions'])
                    actions = flow_match['actions']
        
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        
        output_packet = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(output_packet)
        self._log_packet_departure(dst_mac, out_port)

    def _lookup_port(self, switch_id, mac, ofproto):
        """Find output port for destination MAC"""
        if mac in self.forwarding_table[switch_id]:
            return self.forwarding_table[switch_id][mac]
        return ofproto.OFPP_FLOOD

    def _build_match_rule(self, eth, pkt, in_port, parser, dp, ofp):
        """Construct flow match with redirection logic"""
        result = None
        
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info(f"Flow Rule: ARP [{eth.src} -> {eth.dst}]")
            out_port = self._lookup_port(dp.id, eth.dst, ofp)
            result = {
                'match': parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    in_port=in_port,
                    eth_dst=eth.dst,
                    eth_src=eth.src
                ),
                'actions': [parser.OFPActionOutput(out_port)],
                'final_dst': eth.dst,
                'final_port': out_port
            }
        
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto
            
            if protocol == in_proto.IPPROTO_ICMP:
                self.logger.info(f"Flow Rule: ICMP [{src_ip} -> {dst_ip}]")
                out_port = self._lookup_port(dp.id, eth.dst, ofp)
                result = {
                    'match': parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=protocol,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        in_port=in_port
                    ),
                    'actions': [parser.OFPActionOutput(out_port)],
                    'final_dst': eth.dst,
                    'final_port': out_port
                }
            
            elif protocol == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                
                redirect_info = self._check_redirection(dst_ip, eth.dst, src_ip, eth.src, dp, ofp)
                
                if redirect_info:
                    self.logger.info(
                        f"Flow Rule: TCP Redirect [{src_ip}:{src_port} -> {dst_ip}:{dst_port}] "
                        f"=> {redirect_info['new_ip']}"
                    )
                    result = {
                        'match': parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ip_proto=protocol,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            tcp_src=src_port,
                            tcp_dst=dst_port
                        ),
                        'actions': redirect_info['actions'],
                        'final_dst': redirect_info['new_mac'],
                        'final_port': redirect_info['port']
                    }
                else:
                    self.logger.info(f"Flow Rule: TCP [{src_ip}:{src_port} -> {dst_ip}:{dst_port}]")
                    out_port = self._lookup_port(dp.id, eth.dst, ofp)
                    result = {
                        'match': parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ip_proto=protocol,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            tcp_src=src_port,
                            tcp_dst=dst_port
                        ),
                        'actions': [parser.OFPActionOutput(out_port)],
                        'final_dst': eth.dst,
                        'final_port': out_port
                    }
        
        return result

    def _check_redirection(self, dst_ip, dst_mac, src_ip, src_mac, dp, ofp):
        """Determine if redirection is needed and build redirect actions"""
        parser = dp.ofproto_parser
        
        if dst_ip == self.endpoints['server_primary'].ip and dst_mac == self.endpoints['server_primary'].mac:
            new_mac = self.endpoints['server_backup'].mac
            new_ip = self.endpoints['server_backup'].ip
            port = self._lookup_port(dp.id, new_mac, ofp)
            
            return {
                'new_ip': new_ip,
                'new_mac': new_mac,
                'port': port,
                'actions': [
                    parser.OFPActionSetField(eth_dst=new_mac),
                    parser.OFPActionSetField(ipv4_dst=new_ip),
                    parser.OFPActionOutput(port=port)
                ]
            }
        
        elif dst_ip == self.endpoints['client'].ip and dst_mac == self.endpoints['client'].mac:
            new_mac = self.endpoints['server_primary'].mac
            new_ip = self.endpoints['server_primary'].ip
            port = self._lookup_port(dp.id, dst_mac, ofp)
            
            return {
                'new_ip': new_ip,
                'new_mac': new_mac,
                'port': port,
                'actions': [
                    parser.OFPActionSetField(eth_src=new_mac),
                    parser.OFPActionSetField(ipv4_src=new_ip),
                    parser.OFPActionOutput(port=port)
                ]
            }
        
        return None

    def _log_packet_arrival(self, switch_id, src_mac, dst_mac, in_port):
        """Log incoming packet information"""
        self.logger.info(
            f"\n{'='*60}\n"
            f"Packet In Event\n"
            f"Switch ID: {switch_id}\n"
            f"Source: {src_mac} @ Port {in_port}\n"
            f"Destination: {dst_mac}\n"
            f"{'='*60}"
        )

    def _log_packet_departure(self, dst_mac, out_port):
        """Log outgoing packet information"""
        self.logger.info(
            f"\nPacket Out Event\n"
            f"Target: {dst_mac}\n"
            f"Output Port: {out_port}\n"
        )