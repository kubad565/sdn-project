# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
from ryu.lib.packet import icmp
from ryu import cfg
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ingress_icmp_rule_installed = False

        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('path', default=1, help = ('Selected path'))])

        self.selected_path = CONF.path
        print('path = {}'.format(CONF.path))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    '''
    def create_icmp_request(self, datapath, pkt_ethernet, pkt_ipv4):

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,		#ping source of TCP SYN
                                           src=pkt_ethernet.dst))
        print "Creating ICMP. Dest={}, Src={}".format(pkt_ethernet.src, pkt_ethernet.dst)
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=pkt_ipv4.dst,
                                   proto=1))
        print "Creating ICMP. Dest={}, Src={}, proto={}".format(pkt_ipv4.src, pkt_ipv4.dst, 1)
	rtt_info=str(pkt_ipv4.src)+","+str(time.time())
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST,
                                   code=0,					
                                   csum=0,
                                   data=icmp.echo(1,1,bytearray(rtt_info))))

        pkt_dest = packet.Packet()
        pkt_dest.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.dst,		#ping destination of TCP SYN
                                           src=pkt_ethernet.src))
        print "Creating ICMP. Dest={}, Src={}".format(pkt_ethernet.dst, pkt_ethernet.src)
        pkt_dest.add_protocol(ipv4.ipv4(dst=pkt_ipv4.dst,
                                   src=pkt_ipv4.src,
                                   proto=1))
        print "Creating ICMP. Dest={}, Src={}, proto={}".format(pkt_ipv4.dst, pkt_ipv4.src, 1)
	rtt_info_dest=str(pkt_ipv4.dst)+","+str(time.time())
        pkt_dest.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST,
                                   code=0,					
                                   csum=0,
                                   data=icmp.echo(1,1,bytearray(rtt_info_dest))))


        return [pkt, pkt_dest]    

    def send_icmp(self, datapath, in_port, out_port, pkt_ethernet, pkt_ipv4):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        [icmp_pkt, icmp_pkt_dest] = self.create_icmp_request(datapath, pkt_ethernet, pkt_ipv4)
        icmp_pkt.serialize()
        data=icmp_pkt.data

        actions = [parser.OFPActionOutput(port=out_port)]
        print "Sending ICMP. In={} Out={}".format(out_port, in_port)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        success=datapath.send_msg(out)
        print "icmp packet out={}".format(success)

        icmp_pkt_dest.serialize()
        data=icmp_pkt_dest.data

        actions = [parser.OFPActionOutput(port=in_port)]
        print "Sending ICMP. In={} Out={}".format(in_port, out_port)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=out_port, actions=actions, data=data)
        success=datapath.send_msg(out)
        print "icmp packet out={}".format(success)

    '''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        '''
        elif eth.ethertype == ether_types.ETH_TYPE_IP:            
            ipp = pkt.get_protocol(ipv4.ipv4)
            print "IP packet. Source={} Destination={} Protocol={}".format(ipp.src, ipp.dst, ipp.proto)

            if ipp.proto == 6:
                tcpp = pkt.get_protocol(tcp.tcp)
                if tcpp.has_flags(tcp.TCP_SYN):
                    print "SYN Received from {} at {}".format(ipp.src, datapath.id)
                    if self.ingress_icmp_rule_installed==False:
                        actions_controller_icmp = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                        match_icmp = parser.OFPMatch(eth_type=0x0800,ip_proto=1)
                        self.add_flow(datapath, 3, match_icmp, actions_controller_icmp)
                        self.ingress_icmp_rule_installed = True
                        out_port = self.mac_to_port[datapath.id][eth.dst]
                        self.send_icmp(datapath, out_port, in_port, eth, ipp)#in_port, out_port
            elif ipp.proto == 1:
                if self.ingress_icmp_rule_installed==True:
                    icmpp = pkt.get_protocol(icmp.icmp)
                    rtt_info=str(icmpp.data.data)
                    rtt_info_fields=rtt_info.split(",")
                    rtt=time.time()-float(rtt_info_fields[1])
                    print "RTT calculated. Target = {}, send_time = {}, rtt={}ms".format(rtt_info_fields[0], rtt_info_fields[1], rtt*1000)
                    return
        '''

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        if dpid in [1,6] and in_port==3-self.selected_path:
            #print("ignoring packet")
            return
        
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        actions_controller = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match_tcp = parser.OFPMatch(eth_type=0x0800,ip_proto=6)

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            self.add_flow(datapath, 2, match_tcp, actions_controller)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        success=datapath.send_msg(out)
        #print("Flow rule installed successfully = {}".format(success))
