from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from sklearn.externals import joblib
import numpy as np
import time
NORMAL_TRAFFIC = 0
ATTACK_TRAFFIC = 1

# the file (dpid + filename) saves the information about the switch dpid
filename = "detector_result.log"
traffic_label = NORMAL_TRAFFIC
model_dir = ''

class DDOS_Detector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDOS_Detector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.collector_thread = hub.spawn(self._collector)
        self.collector_period = 5
        self.idle_timeout = 10
        self.mac_to_port = {}
        self.ip_to_port = {}

        self.temp_pkt_num = 0
        self.temp_pkt_byte = 0
        self.temp_ports = 0
        self.temp_flows = 0
        self.sip_num = 0
        self.Sip = []
        self.ip_ports = {}
        #flow_num, port_num, ip_num
        self.records = [0, 0, 0]
        #time, avg_pkt_num, avg_flow_byte, chg_ports, chg_flow, chg_sip, traffic_label
        self.rcd = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    def _collector(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                hub.sleep(self.collector_period)
                self._records(str(dp.id), traffic_label)
                self.reset()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request to datapath: %16x', datapath.id)
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def reset(self):
        self.temp_pkt_num = 0
        self.temp_pkt_byte = 0
        self.temp_ports = 0
        self.temp_flows = 0
        self.sip_num = 0
        self.Sip = []
        self.ip_ports = {}

    def _records(self, dpid, traffic_label):
        if self.temp_flows:
            avg_pkt_num = float(self.temp_pkt_num) / float(self.temp_flows)
        else:
            avg_pkt_num = 0
        if self.temp_flows:
            avg_flow_byte = self.temp_pkt_byte / float(self.temp_flows)
        else:
            avg_flow_byte = 0
        for ip in self.ip_ports:
            self.temp_ports += len(self.ip_ports[ip])
        chg_ports = self.records[1] / float(self.collector_period)
        chg_flow  = self.records[0] / float(self.collector_period)
        chg_sip  = self.records[2] / float(self.collector_period)
        self.rcd[0] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.rcd[1] = avg_pkt_num
        self.rcd[2] = avg_flow_byte
        self.rcd[3] = chg_ports
        self.rcd[4] = chg_flow
        self.rcd[5] = chg_sip
        self.rcd[6] = traffic_label

        clf = joblib.load(model_dir)
        start_time = time.time()
        vec = np.array(self.rcd[1:6]).reshape(1, -1)
        result = clf.predict(vec)
        self.rcd[7] = result[0]
        duration = time.time() - start_time
        if self.rcd[6] == self.rcd[7]:
            self.rcd[8] = 'correct'
        else:
            self.rcd[8] = 'wrong'

        if self.rcd[7] == 1:
            self.rcd[7] = 'attack'
        else:
            self.rcd[7] = 'normal'
        self.rcd[9] = duration
        file = open(dpid+filename, 'ab')
        record = ''
        for item in self.rcd:
            record += str(item) + ' '
        file.write(record + '\n')
        file.close()
        self.sip_num = len(self.Sip)
        self.records[0] = self.temp_flows
        self.records[1] = self.temp_ports
        self.records[2] = self.sip_num

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)

    def add_flow(self, datapath, priority, match, actions, idle_timeout, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.debug('Register datapath: %16x', datapath.id)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.debug('Unregister datapath: %16x', datapath.id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        flow_num = 0
        pktsNum = 0
        byte_counts = 0
        for flow in body:
            if flow.priority == 1:
                self.temp_flows += 1
                self.temp_pkt_byte += flow.byte_count
                self.temp_pkt_num += flow.packet_count
                if flow.match['ip_proto'] == in_proto.IPPROTO_TCP:
                    ip = flow.match['ipv4_src']
                    if ip not in self.ip_ports:
                        self.ip_ports.setdefault(ip, [])
                    tcp_src = flow.match['tcp_src']
                    tcp_dst = flow.match['tcp_dst']
                    if tcp_src not in self.ip_ports[ip]:
                        self.ip_ports[ip].append(tcp_src)
                    ip = flow.match['ipv4_dst']
                    if ip not in self.ip_ports:
                        self.ip_ports.setdefault(ip, [])
                    if tcp_dst not in self.ip_ports[ip]:
                        self.ip_ports[ip].append(tcp_dst)
                if flow.match['ip_proto'] == in_proto.IPPROTO_UDP:
                    ip = flow.match['ipv4_src']
                    if ip not in self.ip_ports:
                        self.ip_ports.setdefault(ip, [])
                    udp_src = flow.match['udp_src']
                    udp_dst = flow.match['udp_dst']
                    if udp_src not in self.ip_ports[ip]:
                        self.ip_ports[ip].append(udp_src)
                    ip = flow.match['ipv4_dst']
                    if ip not in self.ip_ports:
                        self.ip_ports.setdefault(ip, [])
                    if udp_dst not in self.ip_ports[ip]:
                        self.ip_ports[ip].append(udp_dst)
                Src_ip = flow.match['ipv4_src']
                if Src_ip not in self.Sip:
                    self.Sip.append(Src_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # init dpid route
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        # learn MAC
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        # distinguish protocol type
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        # arp msg
        if pkt_arp:
            arp_ip_src = pkt_arp.src_ip
            arp_ip_dst = pkt_arp.dst_ip
            self.ip_to_port[dpid][arp_ip_src] = in_port
            if arp_ip_dst in self.ip_to_port[dpid]:
                out_port = self.ip_to_port[dpid][arp_ip_dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [ofp_parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
            out = ofp_parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=in_port,actions=actions,data=msg.data)
            datapath.send_msg(out)
            return

        if pkt_ipv4:

            ipv4_src = pkt_ipv4.src
            ipv4_dst = pkt_ipv4.dst
            ipv4_proto = pkt_ipv4.proto

            self.ip_to_port[dpid][ipv4_src] = in_port

            if ipv4_dst in self.ip_to_port[dpid]:
                out_port = self.ip_to_port[dpid][ipv4_dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [ofp_parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]

            # There's route in ip_to_port, add_flow
            if out_port != ofproto.OFPP_FLOOD:
                # icmp packet
                if ipv4_proto == in_proto.IPPROTO_ICMP:
                    match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=ipv4_proto,ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                    self.add_flow(datapath, 1, match, actions, self.idle_timeout)
                    return

                # tcp packet
                if ipv4_proto == in_proto.IPPROTO_TCP:
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    tcp_src_port = pkt_tcp.src_port
                    tcp_dst_port = pkt_tcp.dst_port

                    match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=ipv4_proto,ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                                tcp_src=tcp_src_port,tcp_dst=tcp_dst_port)
                    self.add_flow(datapath, 1, match, actions, self.idle_timeout)
                    return

                # udp packet
                if ipv4_proto == in_proto.IPPROTO_UDP:
                    pkt_udp = pkt.get_protocol(udp.udp)
                    udp_src_port = pkt_udp.src_port
                    udp_dst_port = pkt_udp.dst_port

                    match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=ipv4_proto,ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                                udp_src=udp_src_port, udp_dst=udp_dst_port)
                    self.add_flow(datapath, 1, match, actions, self.idle_timeout)
                    return

            out = ofp_parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=in_port,actions=actions,data=msg.data)
            datapath.send_msg(out)
            return
