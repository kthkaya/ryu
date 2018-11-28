import operator
import array
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
from ryu.lib.trapputils import get_protocols, getTrid
from ryu.lib.policydb import PolicyDB
from ryu.lib import dpid

class Trapp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Trapp, self).__init__(*args, **kwargs)
        #Store switches inb a dictionary where dpipd is key and the datapath is the value
        #This is an unordered dictionary of switches
        self.switches = {}
        #This is a list of switches ordered in reverse. Use this for chain rule installation, to install from egress TE first all the way to ingress TE
        self.revSortdSwitches = []
        self.packetInCache ={}
        
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('chainLength', default=0, help = ('SC Chain length')),
            cfg.IntOpt('polDBSize', default = 0, help = ('PolicyDB pre-generated nr of rules'))])

        #self.chLen = CONF.chainLength
        #self.polDBSize = CONF.polDBSize

        chainPol = []
        for x in range(0,CONF.chainLength):
            chainPol.append((8,9))
        
        self.polDB = PolicyDB(chainPol)
        self.polDB.populate(CONF.polDBSize)

    def addSwitch(self,dp):
        self.switches[dp.id] = dp
        #Sorting happens based on the last 2 hex chars of the dpid
        self.revSortdSwitches = sorted(self.switches.items(), key= lambda dpidLast2: hex(dpidLast2[0])[-2:], reverse=True)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.addSwitch(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('\nSwitch enter: %s' % ev)
        print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
        """
        Following is commented out, installing reactively on packetin at the ingress instead
        if ev.switch.dp.id == 0x11223344556677ff:      
            self.installCoreRules()   
        """    
    @set_ev_cls(EventSwitchLeave)
    def _ev_switch_leave_handler(self, ev):
        print('\nSwitch leave: %s' % ev)
        print('\nLeaving DPID: %s' % hex(ev.switch.dp.id))
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
            policy = self.polDB.find(trid)
            #Assign the returned actions to the cached packets
            self.packetInCache[trid][0] = self.installCoreRules(trid, policy)
        
        if self.packetInCache[trid][0]:
            for payload in self.packetInCache[trid][1]:
                #self.logger.info("Unqueueing")
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                    actions=self.packetInCache[trid][0], data=payload)
                dp.send_msg(out)
                self.packetInCache[trid][1].remove(payload)
            #self.packetInCache.pop(trid) Another thread must cleanup this cache
    
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
    
    def installCoreRules(self, trid, policy):
        #print("\nInstalling Core rules")
        #self.logger.info("\nThere are %i switches", len(self.switches))
        polIndex = len(policy)-1
        packetOutActions = []
        for dpid, dp in self.revSortdSwitches:
            #self.logger.info("Rev orderd dpids %s", hex(dpid))
            actions = []
            parser = dp.ofproto_parser
            inPort=policy[polIndex][0]
            outPort=policy[polIndex][1]
            polIndex-=1
            if dpid & 0xff000000000000ff == 0x1100000000000000:
                #The Inbound TE. Match on 5-tuple
                #self.logger.info("It is the ingress TE!")
                match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6, ipv6_src=trid[0], ipv6_dst=trid[1], ip_proto=trid[4], udp_src=trid[2], udp_dst=trid[3])
                actions.append(parser.OFPActionOutput(outPort, 2000))
                packetOutActions = actions
                self.add_flow(dp, 10, match, actions)
                continue
            
            match = parser.OFPMatch(in_port=inPort)
            self.logger.info(match)
            actions.append(parser.OFPActionOutput(outPort, 2000))
            self.logger.info(actions)
            self.add_flow(dp, 10, match, actions)

            """
            Just one way for now
            actions = []
            match = parser.OFPMatch(in_port=9)
            actions.append(parser.OFPActionOutput(8, 2000))
            self.add_flow(dp, 10, match, actions)
            """
        return packetOutActions

