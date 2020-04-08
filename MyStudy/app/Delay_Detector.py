from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import time

class NetworkDelayDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkDelayDetector, self).__init__(*args, **kwargs)
        self.sending_echo_request_interval = 0.05
        self.sw_module = lookup_service_brick('switches')
        self.datapaths = {}
        self.echo_latency = {}
        self.lldp_latency = {}
        self.delay = {}
        self.measure_thread = hub.spawn(self._detector)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _detector(self):
        while True:
            self._send_echo_request()
            self.create_link_delay()
            self.show_delay_statis()
            hub.sleep(5)

    def _send_echo_request(self):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath, data="%.12f" % time.time())
            datapath.send_msg(echo_req)
            hub.sleep(self.sending_echo_request_interval)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        now_timestamp = time.time()
        try:
            latency = now_timestamp - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Parsing LLDP packet and get the delay of link.
        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            dpid = msg.datapath.id
            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')
            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    delay = self.sw_module.ports[port].delay
                    self._save_lldp_delay(src=src_dpid, dst=dpid,lldpdelay=delay)
        except LLDPPacket.LLDPUnknownFormat as e:
            return

    def _save_lldp_delay(self, src=0, dst=0, lldpdelay=0):
        if (src, dst) in self.lldp_latency:
            self.lldp_latency[(src, dst)] = (self.lldp_latency[(src, dst)] + lldpdelay) / 2.0
        else:
            self.lldp_latency[(src, dst)] = lldpdelay

    def create_link_delay(self):
        for item in self.self.lldp_latency:
            delay = self.get_delay(item[0], item[1])
            if item in self.delay:
                self.delay[item] = (self.delay[item] + delay) / 2.0
            else:
                self.delay[item] = delay

    def get_delay(self, src, dst):
        try:
            fwd_delay = self.lldp_latency[(src, dst)]
            re_delay = self.lldp_latency[(dst, src)]
            src_latency = self.echo_latency[src]
            dst_latency = self.echo_latency[dst]
            delay = (fwd_delay + re_delay - src_latency - dst_latency)/2
            return max(delay, 0)
        except:
            return float('inf')

    def show_delay_statis(self):
        self.logger.info("\nsrc   dst      delay")
        self.logger.info("---------------------------")
        for item in self.delay:
            self.logger.info("%s<-->%s : %s" % (item[0], item[1], self.delay[item]))
     

'''
Make some changes in topology/switches.py:

1、Add self.delay for PortData in topology/switches.py module.
class PortData(object):
      def __init__(self, is_down, lldp_data):
          super(PortData, self).__init__()
          self.is_down = is_down
          self.lldp_data = lldp_data
          self.timestamp = None
          self.sent = 0
          self.delay = 0
2、 Add delay calculation code in Class Switches in topology/switches.py module.

@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def packet_in_handler(self, ev):
  	# add code for getting LLDP packet receiving timestamp
      recv_timestamp = time.time()
      if not self.link_discovery:
          return

      msg = ev.msg
      try:
          src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
      except LLDPPacket.LLDPUnknownFormat as e:
          # This handler can receive all the packtes which can be
          # not-LLDP packet. Ignore it silently
          return

      dst_dpid = msg.datapath.id
      if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
          dst_port_no = msg.in_port
      elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
          dst_port_no = msg.match['in_port']
      else:
          LOG.error('cannot accept LLDP. unsupported version. %x',
                    msg.datapath.ofproto.OFP_VERSION)

      # get the lldp delay, and save it into port_data.
      for port in self.ports.keys():
          if src_dpid == port.dpid and src_port_no == port.port_no:
              send_timestamp = self.ports[port].timestamp
              if send_timestamp:
                  self.ports[port].delay = recv_timestamp - send_timestamp
                  
3、reinstall Ryu ： sudo python setup.py install 

4、ryu-manager Delay_Detector.py --observe-links

'''
