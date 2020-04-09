from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp


class MultiTable(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultiTable, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        self.logger.debug("NORMAL")
        req = ofp_parser.OFPTableMod(datapath, 0, 3)
        datapath.send_msg(req)

        self.logger.debug("UDP")
        req = ofp_parser.OFPTableMod(datapath, 1, 3)
        datapath.send_msg(req)


        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)

    def add_flow(self, datapath, priority, match, actions, tableid, gototable, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if gototable == 200:
            goto = parser.OFPInstructionGotoTable(1)
            if buffer_id:
                mod = parser.OFPFlowMod(ofproto.OFPP_ANY, ofproto.OFPG_ANY, ofproto.OFPFF_SEND_FLOW_REM, ofproto.OFPFC_ADD, [goto], match=match,
                                        datapath=datapath, table_id=tableid,priority=priority, buffer_id=buffer_id)
            else:
                mod = parser.OFPFlowMod(ofproto.OFPP_ANY, ofproto.OFPG_ANY, ofproto.OFPFF_SEND_FLOW_REM,ofproto.OFPFC_ADD, [goto], match=match,
                                        datapath=datapath, table_id=tableid,priority=priority)
            datapath.send_msg(mod)
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, table_id=tableid,priority=priority, match=match,instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=tableid,match=match, instructions=inst)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        reader1 = ["94:de:80:42:a6:fb", "94:de:80:42:a6:49", 17]

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = pkt_eth.dst
        src = pkt_eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        if out_port != ofproto.OFPP_FLOOD:
            if pkt_ip is not None and pkt_tcp is None:
                protocol_num = pkt_ip.proto
                if reader1[0] == src and reader1[1] == dst and protocol_num == 17:
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ip_proto=17)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, 0, 0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions, 0, 0)
                if (reader1[0] != src or reader1[1] != dst) and protocol_num == 17:
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ip_proto=17)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, 1, 0, msg.buffer_id)
                        self.add_flow(datapath, 1, match, actions, 0, 200, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions, 1, 0,)
                        self.add_flow(datapath, 1, match, actions, 0, 200)
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            else:
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, 0, 0, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, 0, 0)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
        if out_port == ofproto.OFPP_FLOOD:
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
