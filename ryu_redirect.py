from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, in_proto, tcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


# Host configuration dictionary
hosts = {
    'client': {
        'ip': '10.0.1.5',
        'mac': '00:00:00:00:00:03'
    },
    'server_1': {
        'ip': '10.0.1.2',
        'mac': '00:00:00:00:00:01'
    },
    'server_2': {
        'ip': '10.0.1.3',
        'mac': '00:00:00:00:00:02'
    }
}


class RedirectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RedirectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def _get_output_port(self, dpid, dst_mac):
        """
        Get output port for a given destination MAC address.
        :param dpid: Datapath ID
        :param dst_mac: Destination MAC address
        :return: Output port number or OFPP_FLOOD if unknown
        """
        if dst_mac in self.mac_to_port.get(dpid, {}):
            return self.mac_to_port[dpid][dst_mac]
        else:
            return ofproto_v1_3.OFPP_FLOOD

    def _create_match(self, parser, fields):
        """
        Create an OFPMatch object from a dictionary of fields.
        :param parser: Parser object from datapath
        :param fields: Dictionary of match fields
        :return: OFPMatch object
        """
        # Filter out None values
        filtered_fields = {k: v for k, v in fields.items() if v is not None}
        return parser.OFPMatch(**filtered_fields)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        set up default packetIn rule
        :param ev:
        :return:
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_default(datapath, 0, match, actions)


    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        """
        Unified method to add flow entries
        :param datapath: Datapath object
        :param priority: Flow priority
        :param match: Match conditions
        :param actions: Actions to execute
        :param buffer_id: Buffered packet ID
        :param idle_timeout: Idle timeout for flow entry
        :return: None
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Prepare flow mod parameters
        flow_params = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': inst
        }
        
        # Add buffer_id if present
        if buffer_id:
            flow_params['buffer_id'] = buffer_id
            
        # Add idle timeout if specified
        if idle_timeout > 0:
            flow_params['idle_timeout'] = idle_timeout
            
        # Create and send flow mod message
        mod = parser.OFPFlowMod(**flow_params)
        datapath.send_msg(mod)

    def add_flow_default(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add flow without timeout (wrapper for _add_flow)
        """
        self._add_flow(datapath, priority, match, actions, buffer_id)

    def add_flow_specific(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add flow with timeout (wrapper for _add_flow)
        """
        self._add_flow(datapath, priority, match, actions, buffer_id, idle_timeout=5)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        packetIn handling process
        :param ev:
        :return:
        """
        # extract packet
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        # get physical port
        in_port = msg.match['in_port']
        # get ethernet data
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        src = eth.src
        dst = eth.dst
        # Learn MAC to port mapping
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        # Log packet-in event
        self.logger.info(
            f"\n[PACKET_IN] Switch={dpid} SrcMAC={src} DstMAC={dst} InPort={in_port}"
        )
        
        # Determine output port
        out_port = self._get_output_port(dpid, dst)
        # define packetOut action
        actions = [parser.OFPActionOutput(out_port)]
        # formulate flow table rule
        if out_port != ofproto.OFPP_FLOOD:
            # ARP
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.logger.info(
                    f"[FLOW_ADD] ARP: Switch={dpid} SrcMAC={src} DstMAC={dst} InPort={in_port}"
                )
                match = self._create_match(parser, {
                    'eth_type': ether_types.ETH_TYPE_ARP,
                    'in_port': in_port,
                    'eth_dst': dst,
                    'eth_src': src
                })
            # IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                ip_src = ipv4_pkt.src
                ip_dst = ipv4_pkt.dst
                ip_protocol = ipv4_pkt.proto
                # ICMP
                if ip_protocol == in_proto.IPPROTO_ICMP:
                    self.logger.info(
                        f"[FLOW_ADD] ICMP: Switch={dpid} Proto={ip_protocol} SrcIP={ip_src} DstIP={ip_dst} InPort={in_port}"
                    )
                    match = self._create_match(parser, {
                        'eth_type': ether_types.ETH_TYPE_IP,
                        'ip_proto': ip_protocol,
                        'ipv4_src': ip_src,
                        'ipv4_dst': ip_dst,
                        'in_port': in_port
                    })
                # TCP
                elif ip_protocol == in_proto.IPPROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    tcp_src_port = tcp_pkt.src_port
                    tcp_dst_port = tcp_pkt.dst_port
                    # Handle TCP traffic redirection
                    if ip_dst == hosts['server_1']['ip'] and dst == hosts['server_1']['mac']:
                        # Redirect: client -> server_1 -> server_2
                        match = self._create_match(parser, {
                            'eth_type': ether_types.ETH_TYPE_IP,
                            'ip_proto': ip_protocol,
                            'ipv4_src': ip_src,
                            'ipv4_dst': ip_dst,
                            'tcp_src': tcp_src_port,
                            'tcp_dst': tcp_dst_port
                        })
                        self.logger.info(
                            f"[FLOW_ADD] TCP: Switch={dpid} Proto={ip_protocol} SrcIP={ip_src} DstIP={ip_dst} SrcPort={tcp_src_port} DstPort={tcp_dst_port} (Redirected)"
                        )
                        # Modify destination to server_2
                        ip_dst = hosts['server_2']['ip']
                        dst = hosts['server_2']['mac']
                        out_port = self._get_output_port(dpid, dst)
                        actions = [
                            parser.OFPActionSetField(eth_dst=dst),
                            parser.OFPActionSetField(ipv4_dst=ip_dst),
                            parser.OFPActionOutput(port=out_port)
                        ]
                    elif ip_dst == hosts['client']['ip'] and dst == hosts['client']['mac']:
                        # Rewrite response: server_2 -> client (as if from server_1)
                        match = self._create_match(parser, {
                            'eth_type': ether_types.ETH_TYPE_IP,
                            'ip_proto': ip_protocol,
                            'ipv4_src': ip_src,
                            'ipv4_dst': ip_dst,
                            'tcp_src': tcp_src_port,
                            'tcp_dst': tcp_dst_port
                        })
                        self.logger.info(
                            f"[FLOW_ADD] TCP: Switch={dpid} Proto={ip_protocol} SrcIP={ip_src} DstIP={ip_dst} SrcPort={tcp_src_port} DstPort={tcp_dst_port} (Rewritten)"
                        )
                        # Modify source to server_1
                        ip_src = hosts['server_1']['ip']
                        src = hosts['server_1']['mac']
                        out_port = self._get_output_port(dpid, dst)
                        actions = [
                            parser.OFPActionSetField(eth_src=src),
                            parser.OFPActionSetField(ipv4_src=ip_src),
                            parser.OFPActionOutput(port=out_port)
                        ]
            # invoke add flow method
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow_specific(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow_specific(datapath, 1, match, actions)
        # check msg data
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # define output packet
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        # packetOut
        datapath.send_msg(out)
        # packetOut logger
        self.logger.info(
            f"[PACKET_OUT] DstMAC={dst} OutPort={out_port}"

        )
