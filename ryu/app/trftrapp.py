import operator
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import addrconv
from ryu.lib.pack_utils import msg_pack_into
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet.ether_types import ETH_TYPE_IPV6
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3
from ryu.topology import switches
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
import struct

from ryu.lib.policydb import PolicyDB
from ryu.lib.trapputils import get_protocols, getTrid


class Trapp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Trapp, self).__init__(*args, **kwargs)
        #Store switches inb a dictionary where dpipd is key and the datapath is the value
        self.switches = {}
        self.packetInCache ={}
        #Temporary solution, tlvstack shouldnt be per controller, should be per flow
        self.tlvStack = bytearray()
        
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('chainLength', default=0, help = ('SC Chain length')),
            cfg.IntOpt('polDBSize', default = 0, help = ('PolicyDB pre-generated nr of rules')),
            cfg.IntOpt('flowTimeout', default = 0, help = ('Flow rule timeout for the ingress TE rules'))])

        #self.chLen = CONF.chainLength
        #self.polDBSize = CONF.polDBSize
        self.flowTimeout = CONF.flowTimeout
        self.tlvStack = self.packTLVs(CONF.chainLength-1, 0)
        self.polDB = PolicyDB(self.tlvStack)
        self.polDB.populate(CONF.polDBSize)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switches[datapath.id] = datapath

        print ("Switch DPID %s", hex(datapath.id))

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)
    
    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        #print('\nSwitch enter: %s' % ev)
        #print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
        if ev.switch.dp.id == 0x11223344556677ff:      
            self.installCoreRules()   
            
    @set_ev_cls(EventSwitchLeave)
    def _ev_switch_leave_handler(self, ev):
        #print('\nSwitch leave: %s' % ev)
        #print('\nLeaving DPID: %s' % hex(ev.switch.dp.id))
        self.switches.pop(ev.switch.dp.id)
        if len(self.switches) < 1:
            self.packetInCache ={}
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
            Following is coded trusting that only the ingress TE will send packet_in.
            So make sure chaining starts from the exit TE, all the way up to the ingress TE. 
        """
        #self.logger.info("Incoming packet")
        msg = ev.msg               # Object representing a packet_in data structure.
        dp = msg.datapath          # Switch Datapath ID
        parser = dp.ofproto_parser 
        trid = getTrid(msg.data)
        
        if trid in self.packetInCache:
            #A packet with the same 5-tuple has already arrived. Cache this one.                 
            packetBuf = self.packetInCache[trid][1]
            if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER:
                #self.logger.info("Queueing")
                packetBuf.append(msg.data)
        
        else:
            #First time seeing this 5-tuple. Cache the payload and lookup the header in polDB
            packetBuf = []
            actions = []
            if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER:
                packetBuf.append(msg.data)
            self.packetInCache[trid] = [actions, packetBuf]
        
            #if dp.id & 0xff00000000000000 == 0x1100000000000000:
            #The Inbound TE.          
            tlvStack = self.polDB.find(trid)
            trhLen= 5 + len(self.tlvStack)/8
            
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6, ipv6_src=trid[0], ipv6_dst=trid[1], ip_proto=trid[4], udp_src=trid[2], udp_dst=trid[3])
            #Following will fail if a packet comes in before the full chain is deployed
            actions.append(parser.OFPActionPushTrh(length=trhLen, nextuid=0x3b4d0100, tlvs=tlvStack))
            actions.append(parser.OFPActionOutput(9, 2000))
            self.add_flow(dp, 15, match, actions, self.flowTimeout)
            
            #Assign the returned actions to the cached packets
            self.packetInCache[trid][0] = actions
        
        if self.packetInCache[trid][0]:
            for payload in self.packetInCache[trid][1]:
                #self.logger.info("Unqueueing")
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                    actions=self.packetInCache[trid][0], data=payload)
                dp.send_msg(out)
                self.packetInCache[trid][1].remove(payload)
            #self.packetInCache.pop(trid) Another thread must cleanup this cache

    def add_flow(self, datapath, priority, match, actions, hardTimeout=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        elif hardTimeout:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, hard_timeout=hardTimeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)
         
        
    def packTLVs(self, tlvCount, hasPayload):
        tlvPackBuf = bytearray()
        nextUID = 0x3b4d01
        offset = 0
        hvnf_vltp= 0xaaaaaaaaaaaaaaaa
                
        for i in range(tlvCount):
              
            if hasPayload:
                TLV_PACK_STR = "!IQ"
                hvnf_uid_len = (nextUID << 8) | 1    
                msg_pack_into(TLV_PACK_STR, tlvPackBuf, offset, hvnf_uid_len, hvnf_vltp)
            else:
                TLV_PACK_STR = "!I"
                hvnf_uid_len = (nextUID << 8) | 0
                msg_pack_into(TLV_PACK_STR, tlvPackBuf, offset, hvnf_uid_len)
                
            offset+=struct.calcsize(TLV_PACK_STR)
            nextUID+=1
                   
        return tlvPackBuf
    
    def installCoreRules(self):
        #TE Switch DPIDs start with ee
        TEMask = 0xff00000000000000
        nextUID = 0x3b4d01
        #print("\nInstalling Core rules")
        #self.logger.info("\nThere are %i switches", len(self.switches))
            
        for dpid, dp in self.switches.iteritems():
            #self.logger.info("\nSwitch loooopn DPID: %s", hex(dpid))           
            actions = []
            parser = dp.ofproto_parser
            if dpid & TEMask != 0x1100000000000000:
                #Not a TE. Install matchnextuid + setnextuid action.
                match = parser.OFPMatch(in_port=8, trh_nextuid=nextUID<<8, eth_type=ETH_TYPE_IPV6)
                actions.append(parser.OFPActionSetTrhNextuid())
                actions.append(parser.OFPActionOutput(9, 2000))
                nextUID+=1
                self.add_flow(dp, 10, match, actions)
                continue
        
            elif dpid & 0x00000000000000ff == 0x00000000000000ff:
                #The exit TE. 
                match = parser.OFPMatch(in_port=8, trh_nextuid=nextUID<<8, eth_type=ETH_TYPE_IPV6)
                actions.append(parser.OFPActionPopTrh())
                actions.append(parser.OFPActionOutput(9, 2000))
                self.add_flow(dp, 10, match, actions)
