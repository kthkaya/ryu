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
        #parser = datapath.ofproto_parser
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
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                  ofproto.OFPCML_NO_BUFFER)]
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        """
        
        #action=LOCAL for each bridge's IP address for bridge to own its IP (ARP res etc.)
        dpidLast2= hex(datapath.id)[16:]
        if "ff" in dpidLast2:
            dstIP="192.168.10."+str(len(self.switches))
            self.installTunPrereq(datapath, dstIP, ofproto.OFPP_LOCAL)
        elif dpidLast2 != '':
            dstIP="192.168.10."+str(int(dpidLast2,16)+1)
            self.installTunPrereq(datapath, dstIP, ofproto.OFPP_LOCAL)
        
    
    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('\nSwitch enter: %s' % ev)
        print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
        if ev.switch.dp.id == 0x11223344556677ff:      
            #self.installCoreRules()
            print('\nWe have an exit TE! Calling chainByVXLAN')
            self.chainByVXLAN()
            
            
            #(TEMP) Prepare the TLVs too 
            self.tlvStack = self.packTLVs(len(self.switches)-1, 0)   
            
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
            
            match = parser.OFPMatch(in_port=1, eth_type=ETH_TYPE_IPV6)
            #Following will fail if a packet comes in before the full chain is deployed
            actions.append(parser.OFPActionPushTrh(length=trhLen, nextuid=0x3b4d0100, tlvs=self.tlvStack))
            actions.append(parser.OFPActionOutput(2, 2000))
            #self.add_flow(dp, 10, match, actions)
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
        print("\nInstalling Core rules")
        self.logger.info("\nThere are %i switches", len(self.switches))
        
       
        for dpid, dp in self.switches.iteritems():
            self.logger.info("\nSwitch loooopn DPID: %s", hex(dpid))
            
            actions = []
            parser = dp.ofproto_parser
            if dpid & TEMask != 0x1100000000000000:
                #Not a TE. Install matchnextuid + setnextuid action.
                match = parser.OFPMatch(in_port=1, trh_nextuid=nextUID, eth_type=ETH_TYPE_IPV6)
                actions.append(parser.OFPActionSetTrhNextuid())
                actions.append(parser.OFPActionOutput(2, 2000))
                nextUID+=1
                self.add_flow(dp, 10, match, actions)
                continue
        
            elif dpid & 0x00000000000000ff == 0x00000000000000ff:
                #The exit TE 
                match = parser.OFPMatch(in_port=1, trh_nextuid=nextUID, eth_type=ETH_TYPE_IPV6)
                actions.append(parser.OFPActionPopTrh())
                actions.append(parser.OFPActionOutput(2, 2000))
                self.add_flow(dp, 10, match, actions)
     
    def chainByVXLAN(self):
        print("\VXLAN Chaining")
        TEMask = 0xff00000000000000
        #VLAN ID
        s_vid = 100
        tunnelId = 50 
        
        for dpid, dp in self.switches.iteritems():
            print("\nVXLAN Chaining DPID: %s", hex(dpid))
            actions = []
            parser = dp.ofproto_parser
            match = parser.OFPMatch()
            
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
                match.set_in_port(8)
                match.set_tunnel_id(tunnelId)
                match.set_vlan_vid(s_vid | dp.ofproto.OFPVID_PRESENT)
                actions.append(parser.OFPActionPopVlan())
                actions.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                actions.append(parser.OFPActionSetField(vlan_vid= (s_vid+100) | dp.ofproto.OFPVID_PRESENT))
                actions.append(parser.OFPActionSetField(ofTunId))
                actions.append(parser.OFPActionOutput(9, 2000))
                
                s_vid+=100
                                
            elif dpid & 0x00000000000000ff == 0x00000000000000ff:
                #The exit TE 

                """
                    Install rules for tunnel neighbor switch on the left
                """
                dpidLast2= hex(dpid)[16:]
                leftNeighIP="192.168.10."+str(len(self.switches)-1)
                self.installTunPrereq(dp, leftNeighIP, 1)
                
                
                match.set_in_port(8)
                match.set_tunnel_id(tunnelId)
                match.set_vlan_vid(s_vid)
                
                actions.append(parser.OFPActionPopVlan())
                actions.append(parser.OFPActionOutput(9, 2000))
                
            elif dpid :
                #The ingress TE
                print("Ingress TE")
                match.set_in_port(8)
                f = dp.ofproto_parser.OFPMatchField.make(dp.ofproto.OXM_OF_VLAN_VID, 100)
                
                actions.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                actions.append(parser.OFPActionSetField(vlan_vid= (s_vid) | dp.ofproto.OFPVID_PRESENT))
                actions.append(parser.NXActionSetTunnel(tunnelId))
                
                
                actions.append(parser.OFPActionOutput(9, 2000))
                
                """
                    Install rules for tunnel neighbor switch on the right
                """
                dpidLast2= hex(dpid)[16:]
                rightNeighIP="192.168.10.2"
                self.installTunPrereq(dp, rightNeighIP, 1)
                
            
            self.add_flow(dp, 10, match, actions)


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
        
    def packetParser(self, msgData):
        # parse
        pkt = packet.Packet(msgData)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
       
        self.logger.info("\n-----------------------------")
        self.logger.info("\----Packet Print-------------")
        self.logger.info("\L2= type:%s src:%s dst:%s", p_eth.ethertype, p_eth.src, p_eth.dst)
        if p_eth.ethertype == int(ether.ETH_TYPE_ARP,16) :
            p_arp = protocols['arp']
            self.logger.info("\ARP= srcMac:%s srcIP:%s dstMac:%s dstIP:%s", p_arp.src_mac,p_arp.src_ip,p_arp.dst_mac,p_arp.dst_ip)
        elif p_eth.ethertype == int(ether.ETH_TYPE_IP,16) :
            p_ipv4 = protocols['ipv4']
            self.logger.info("\L3= src:%s dst:%s proto:%s ",p_ipv4.src,p_ipv4.dst,p_ipv4.proto)
            p_udp = protocols['udp']
            self.logger.info("\L4= UDP src:%s dst:%s",p_udp.src_port,p_udp.dst_port)
    
    """
        Get protocols from packet such as  ethernet, arp, ipv4 etc.
    """
    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols
        
