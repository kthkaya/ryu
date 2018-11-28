from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet.ether_types import ETH_TYPE_IPV6
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
import struct

from ryu.lib.policydb import PolicyDB
from ryu.lib.trapputils import get_protocols, getTrid


class Trapp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Trapp, self).__init__(*args, **kwargs)
        #Store switches in a dictionary where dpipd is key and the datapath is the value
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
        sVid = 100
        for x in range(0,CONF.chainLength):
            chainPol.append((sVid,8,sVid+100,9))
            sVid+=100
        
        self.polDB = PolicyDB(chainPol)
        self.polDB.populate(CONF.polDBSize)
    
    def addSwitch(self,dp):
        self.switches[dp.id] = dp
        #Sorting happens based on the last 2 hex chars of the dpid
        self.revSortdSwitches = sorted(self.switches.items(), key= lambda dpidLast2: hex(dpidLast2[0])[-2:], reverse=True)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.addSwitch(datapath)
        #print ("Switch DPID %s", hex(datapath.id))

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        #action=LOCAL for each bridge's IP address for bridge to own its IP (ARP res etc.)
        dpidLast2= hex(datapath.id)[16:]
        if "ff" in dpidLast2:
            dstIP="192.168.10."+str(len(self.switches))
            self.installTunPrereq(datapath, dstIP, ofproto.OFPP_LOCAL)
        elif dpidLast2 != '':
            dstIP="192.168.10."+str(int(dpidLast2,16)+1)
            self.installTunPrereq(datapath, dstIP, ofproto.OFPP_LOCAL)
        
    """
    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('\nSwitch enter: %s' % ev)
        print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
    
        Following is commented out, installing reactively on packetin at the ingress instead
        if ev.switch.dp.id == 0x11223344556677ff:      
            print('\nWe have an exit TE! Calling chainByVXLAN')
            self.chainByVXLAN()   
    """
            
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
            policy = self.polDB.find(trid)
            #Assign the returned actions to the cached packets
            self.packetInCache[trid][0] = self.chainByVXLAN(trid, policy)
        
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
     
    def chainByVXLAN(self, trid, policy):
        TEMask = 0xff00000000000000
        tunnelId = 50 
        packetOutActions = []
        polIndex = len(policy)-1
        
        for dpid, dp in self.revSortdSwitches:
            #print("\nVXLAN Chaining DPID: %s", hex(dpid))
            actions = []
            parser = dp.ofproto_parser
            match = parser.OFPMatch()
            inVlan = policy[polIndex][0]
            inPort = policy[polIndex][1]
            outVlan = policy[polIndex][2]
            outPort = policy[polIndex][3]
            polIndex-=1
            
            ofTunId = parser.OFPMatchField.make(dp.ofproto.OXM_OF_TUNNEL_ID, tunnelId)
            
            if dpid & TEMask == 0x2200000000000000:
                #Switches between TEs
                """
                    Install rules for tunnel neighbors switches on the left and right 
                """
                dpidLast2= hex(dpid)[16:]
                if "ff" in dpidLast2:
                    continue
                leftNeighIP="192.168.10."+str(int(dpidLast2,16))
                rightNeighIP="192.168.10."+str(int(dpidLast2,16)+2)
                self.installTunPrereq(dp, leftNeighIP, 1)
                self.installTunPrereq(dp, rightNeighIP, 2)
                
                """
                    Install SC rules via VXLAN
                """
                ofTunId = parser.OFPMatchField.make(dp.ofproto.OXM_OF_TUNNEL_ID, tunnelId)
                match.set_in_port(inPort)
                match.set_tunnel_id(tunnelId)
                match.set_vlan_vid(inVlan | dp.ofproto.OFPVID_PRESENT)
                actions.append(parser.OFPActionPopVlan())
                actions.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                actions.append(parser.OFPActionSetField(vlan_vid= outVlan | dp.ofproto.OFPVID_PRESENT))
                actions.append(parser.OFPActionSetField(ofTunId))
                actions.append(parser.OFPActionOutput(outPort, 2000))
                                
            elif dpid & 0x00000000000000ff == 0x00000000000000ff:
                #The exit TE 
                """
                    Install rules for tunnel neighbor switch on the left
                """
                
                dpidLast2= hex(dpid)[16:]
                leftNeighIP="192.168.10."+str(len(self.switches)-1)
                self.installTunPrereq(dp, leftNeighIP, 1)               
                
                match.set_in_port(inPort)
                match.set_tunnel_id(tunnelId)
                match.set_vlan_vid(inVlan)              
                actions.append(parser.OFPActionPopVlan())
                actions.append(parser.OFPActionOutput(outPort, 2000))
                
            elif dpid:
                #The ingress TE
                match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6, ipv6_src=trid[0], ipv6_dst=trid[1], ip_proto=trid[4], udp_src=trid[2], udp_dst=trid[3])
                actions.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                actions.append(parser.OFPActionSetField(vlan_vid= outVlan | dp.ofproto.OFPVID_PRESENT))
                actions.append(parser.NXActionSetTunnel(tunnelId))
                actions.append(parser.OFPActionOutput(outPort, 2000))
                packetOutActions = actions
                """
                    Install rules for tunnel neighbor switch on the right
                """
                dpidLast2= hex(dpid)[16:]
                rightNeighIP="192.168.10.2"
                self.installTunPrereq(dp, rightNeighIP, 1)
                
            if actions:
                self.add_flow(dp, 10, match, actions)

        return packetOutActions
    
    def ipv4_to_int(self, ip_text):
        if ip_text == 0:
            return ip_text
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]      
        
    """
        ARP and Next-Hop rules for VXLAN tunnels
    """
    def installTunPrereq(self, datapath, tunDstIP, dstPort):
        
        nw_dst_int = self.ipv4_to_int(tunDstIP)
        
        nwMatch = datapath.ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_tpa=nw_dst_int)       
        nwActions = [datapath.ofproto_parser.OFPActionOutput(dstPort)]
        self.add_flow(datapath, 1, nwMatch, nwActions)
        nwMatch = datapath.ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=nw_dst_int)
        self.add_flow(datapath, 1, nwMatch, nwActions)
        