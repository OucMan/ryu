from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib.packet.packet import packet, ether_types
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ethernet import arp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet import in_proto
from ryu.lib import addrconv
from ryu.lib import mac
import struct
import time

class FireWall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(FireWall,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.internal_host = ['10.0.0.1', '10.0.0.2']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)

    def add_flow(self, datapath, priority, match, actions, idle_timeout, hard_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)

            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            pkt_arp = pkt.get_protocol(arp.arp)
            if pkt_arp:
                arp_ip_src = pkt_arp.src_ip
                self.ip_to_port[dpid][arp_ip_src] = in_port
                actions = [ofp_parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
                out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                              actions=actions, data=msg.data)
                datapath.send_msg(out)
                return
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                ipv4_src = pkt_ipv4.src
                ipv4_dst = pkt_ipv4.dst
                self.ip_to_port[dpid][ipv4_src] = in_port
                ipv4_proto = pkt_ipv4.proto
                if ipv4_proto == in_proto.IPPROTO_TCP:
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    if pkt_tcp.bits == tcp.TCP_SYN and ipv4_src not in self.internal_host:
                        return
                if ipv4_dst in self.ip_to_port[dpid]:
                    out_port = self.ip_to_port[dpid][ipv4_dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                actions = [ofp_parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=ipv4_proto,
                                                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                    self.add_flow(datapath, 1, match, actions)
                    out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                                  actions=actions, data=msg.data)
                    datapath.send_msg(out)
