from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu import cfg
from ryu.lib import hub
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ingress_icmp_rule_installed = False
        self.datapaths = {}
        self.flow_datapaths ={}
        self.monitor_thread = hub.spawn(self._monitor)
        self.prev_sec=0
        self.prev_nsec = 0
        self.prev_bytes = 0
        self.traffic_bw = 0
        self.installed_flows={}
        self.am_deleting=0

        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('bandwidth', default=500000, help = ('Bandwidth threshold'))])

        self.thbandwidth = CONF.bandwidth
        self.selected_path = 1
        print('bandwidth = {}'.format(CONF.bandwidth))

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        print('send stats request: {}'.format(datapath.id) )
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        
        self.logger.info('datapath         '
                         'in-port            '
                         'out-port packets  bytes    sec       bw    nsec')
        self.logger.info('---------------- '
                         '-------- '
                         '-------- -------- -------- -------- -------- -----------')

        
        
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'])):

            self.logger.info('%016x %17s %8x %8d %8d %8d %8d %d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], 
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count, stat.duration_sec, 0, stat.duration_nsec)

            bw=0
            if self.prev_bytes==0:
                self.prev_bytes=stat.byte_count
                self.prev_sec=stat.duration_sec
                self.prev_nsec=stat.duration_nsec
            elif stat.byte_count==self.prev_bytes:
                self.traffic_bw=0
            elif stat.byte_count>self.prev_bytes:
                interval_sec=(stat.duration_sec-self.prev_sec)+(stat.duration_nsec-self.prev_nsec)/1e9
                if interval_sec>0:
                    bw=(stat.byte_count-self.prev_bytes)*8.0/interval_sec
                    bwkb=bw/1000
                    path=1
                    if bwkb>self.thbandwidth:
                        path=2

                    print("bwkb={}, th={}, path={}, selected={}".format(bwkb, self.thbandwidth, path, self.selected_path))

                    if path!=self.selected_path:
                        print("---------------PATH TO BE UPDATED-----------")
                        self.selected_path=path
                        self.am_deleting=1
                        self.clear_flows()
                        self.am_deleting=0
                        self.mac_to_port = {}
                        self.update_flows()
                        
                    if bw>self.traffic_bw:
                        self.traffic_bw=bw
                #print("byte, prev_byte={}, {}".format(stat.byte_count,self.prev_bytes))
                self.prev_bytes=stat.byte_count
                self.prev_sec=stat.duration_sec
                self.prev_nsec=stat.duration_nsec
            
            
            

    def update_flows(self):
        for dp in self.installed_flows:
            datapath=self.installed_flows[dp]
            if self.selected_path==1:
                if dp in [2,3]:
                    self.add_flow_p(datapath, 1, 1, 2)
                    self.add_flow_p(datapath, 1, 2, 1)
                    
                elif datapath.id in [1,6]:
                    self.add_flow_p(datapath, 1, 1, 3)
                    self.add_flow_p(datapath, 1, 3, 1)
                    
            elif self.selected_path==2:
                if dp in [4,5]:
                    self.add_flow_p(datapath, 1, 1, 2)
                    self.add_flow_p(datapath, 1, 2, 1)
                    
                elif datapath.id in [1,6]:
                    self.add_flow_p(datapath, 1, 2, 3)
                    self.add_flow_p(datapath, 1, 3, 2)
                    

            #self.add_flow_p(self.installed_flows[dp], 1, self.selected_path, 3)
            #self.add_flow_p(self.installed_flows[dp], 1, 3, self.selected_path)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        self.installed_flows[datapath.id]=datapath
        print("state_change_handler: datapath={}".format(datapath.id))
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                
                if datapath.id in [2,3]:
                    self.add_flow_p(datapath, 1, 1, 2)
                    self.add_flow_p(datapath, 1, 2, 1)
                    
                elif datapath.id in [1,6]:
                    self.add_flow_p(datapath, 1, 1, 3)
                    self.add_flow_p(datapath, 1, 3, 1)
                
                if datapath.id==1:
                    self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print("feature_handler: datapath={}".format(datapath))

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

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        #print("\n\n===FLOW REMOVED===\n\n")
        if dp.id==1:
            self.prev_sec=0
            self.prev_nsec = 0
            self.prev_bytes = 0
            self.traffic_bw = 0
        '''
        self.logger.info('OFPFlowRemoved received: '
                        'cookie=%d priority=%d reason=%s table_id=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'idle_timeout=%d hard_timeout=%d '
                        'packet_count=%d byte_count=%d match.fields=%s',
                        msg.cookie, msg.priority, reason, msg.table_id,
                        msg.duration_sec, msg.duration_nsec,
                        msg.idle_timeout, msg.hard_timeout,
                        msg.packet_count, msg.byte_count, msg.match)
        '''
    
    def del_flow(self, datapath):
        print("Deleting flow for S{}".format(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=1, eth_src=1, eth_dst=2)

        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, 
                                    cookie=1, cookie_mask=0xFFFFFFFFFFFFFFFF,
                                    table_id=ofproto.OFPTT_ALL,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
        
        datapath.send_msg(mod)

    def clear_flows(self):
        dpl=[]
        if self.selected_path==1:
            dpl=[1,2,3,6]
        else:
            dpl=[1,4,5,6]
        for dp in self.installed_flows:
            self.del_flow(self.installed_flows[dp])
        
        #self.installed_flows={}


    def add_flow_p(self, datapath, priority, in_port, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port)
        self.add_flow(datapath, priority, match, actions, flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=1)
    
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, flags=0, cookie=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(cookie=cookie, datapath=datapath, buffer_id=buffer_id, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(cookie=cookie, datapath=datapath, priority=priority, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags,
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
        return
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

        if self.am_deleting==1:
            return

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
        #match_tcp = parser.OFPMatch(eth_type=0x0800,ip_proto=6)

        #print("====PACKETIN RECEIVED===== {}, {}, {}".format(datapath.id, src, dst))
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            #self.add_flow(datapath, 2, match_tcp, actions_controller)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            idle_=0
            hard_=0
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=idle_, hard_timeout=hard_, flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=1)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=idle_, hard_timeout=hard_, flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=1)

            if datapath.id not in self.installed_flows:
                self.installed_flows[datapath.id]=[]

            self.installed_flows[datapath.id]=datapath

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        success=datapath.send_msg(out)
        #print("Flow rule installed successfully = {}".format(success))
