from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app.rest_router import ipv4_text_to_int, ipv4_int_to_text
from ryu.lib.packet import ipv4, udp
FLOW_PRIORITY = 200

'''
Use meter table to achieve rate limiting
'''
class RateLimiter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RateLimiter, self).__init__(*args, **kwargs)
        self.qos_rule = []
        self.mac_to_port = {}
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    def add_meter_instance(self, datapath, meter_id, max_rate):
        if None in [datapath, meter_id, max_rate]:
            raise Exception('Null parameter!!')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("Add Meter {}: max_rate {}".format(meter_id, max_rate))
        bands = [parser.OFPMeterBandDrop(int(max_rate))]
        mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,
                                 meter_id=int(meter_id), bands=bands)
        datapath.send_msg(mod)

    def add_qos_rule_flow(self, datapath, dst_ip, meter_id, buffer_id=None):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        match.set_ipv4_dst(ipv4_text_to_int(dst_ip.encode('utf8')))
        match.set_dl_type(0x800)
        if self.ip_to_mac.get(dst_ip, None) in self.mac_to_port.get(dpid, {}):
            print("Add QoS flow: dst_ip {}, dst_port {} => Meter {}".format(dst_ip, dst_port, meter_id))
            out_port = self.mac_to_port[dpid][self.ip_to_mac[dst_ip]]
        else:
            return
        # Go meter before apply actions
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionMeter(int(meter_id), ofproto.OFPIT_METER),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=FLOW_PRIORITY, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=FLOW_PRIORITY,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        if not ip:
            return
        dst_ip = ip.dst
        src_ip = ip.src
        self.ip_to_mac[dst_ip] = dst_mac
        self.ip_to_mac[src_ip] = src_mac
        # check if there is an qos_rule matching
        for _meter_id, _dst_ip, _max_rate in self.qos_rule:
            if _dst_ip == dst_ip:
                self.add_meter_instance(datapath, _meter_id, _max_rate)
                self.add_qos_rule_flow(datapath, dst_ip, _meter_id)
                return

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
        
