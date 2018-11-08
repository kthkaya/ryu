from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
from ryu.topology import switches
from ryu.controller.handler import set_ev_cls
from ryu.lib.pack_utils import msg_pack_into
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet.ether_types import ETH_TYPE_IPV6
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib import addrconv
import struct


class Trapp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Trapp, self).__init__(*args, **kwargs)
        #Store switches inb a dictionary where dpipd is key and the datapath is the value
        self.switches = {}
        self.mac_to_port = {}
        #Temporary solution, tlvstack shouldnt be per controller, should be per flow
        self.tlvStack = bytearray()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switches[datapath.id] = datapath

        print ("Switch DPID %s", hex(datapath.id))

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
              
        """              
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
        #                                  ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        """
    
    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('\nSwitch enter: %s' % ev)
        print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
        if ev.switch.dp.id == 0x11223344556677ff:      
            self.installCoreRules()   
            
    @set_ev_cls(EventSwitchLeave)
    def _ev_switch_leave_handler(self, ev):
        print('\nSwitch leave: %s' % ev)
        print('\nLeaving DPID: %s' % hex(ev.switch.dp.id))
        self.switches.pop(ev.switch.dp.id)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        
        msg = ev.msg               # Object representing a packet_in data structure.
        dp = msg.datapath          # Switch Datapath ID
        ofproto = dp.ofproto       # OpenFlow Protocol version the entities negotiated. In our case OF1.3
        parser = dp.ofproto_parser 
        actions = []
        
        """
        if dp.id == 0x1122334455667700:
            #The Inbound TE. Install push_trh
            trhLen= 5 + len(self.tlvStack)/8
            
            match = parser.OFPMatch(in_port=5, eth_type=ETH_TYPE_IPV6)
            #Following will fail if a packet comes in before the full chain is deployed
            actions.append(parser.OFPActionPushTrh(length=trhLen, nextuid=0x3b4d0100, tlvs=self.tlvStack))
            actions.append(parser.OFPActionOutput(9, 2000))
            self.add_flow(dp, 10, match, actions)
        """
               
        #self.logger.info("\n--------PACKET_IN--------")
        #self.logger.info("\Switch: %s, in_port: %s",hex(dp.id),msg.match['in_port'])
        #self.packetParser(msg.data)                     
        
        """
        #if dp.id == 0x1122334455667700:
        if in_port == ofproto.OFPP_LOCAL:
            self.logger.info("\nIn port is LOCAL")
        elif in_port == 1:
            self.logger.info("\nIn port is VETH")
            actions.append(parser.OFPActionOutput(ofproto.OFPP_LOCAL))
        """     
        
        #Installing a flow rule
        #1. Create the match
        #msg = ev.msg
        #in_port = msg.match['in_port']
        # Get the destination ethernet address
        #pkt = packet.Packet(msg.data)
        #eth = pkt.get_protocol(ethernet.ethernet)
        #dst = eth.dst

        
        
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
    
    def installCoreRules(self):
        print("\nInstalling Core rules")
        self.logger.info("\nThere are %i switches", len(self.switches))
       
        for dpid, dp in self.switches.iteritems():
            actions = []
            parser = dp.ofproto_parser
            self.logger.info("\nSwitch loooopn DPID: %s", hex(dpid))
            
            match = parser.OFPMatch(in_port=8)
            actions.append(parser.OFPActionOutput(9, 2000))
            self.add_flow(dp, 10, match, actions)    
