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
        #Temporary solution, tlvstack shouldnt be per controller, should be per flow
        self.tlvStack = bytearray()

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
        print('\nSwitch enter: %s' % ev)
        print('\nDPID: %s' % hex(ev.switch.dp.id))
        
        #Install forwarding rules in the core when the final switch (TE) of the chain is deployed
        #The final TE has the last two chars ff in dpid
        if ev.switch.dp.id == 0x11223344556677ff:      
            self.installCoreRules()
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
        
        if dp.id & 0xff00000000000000 == 0x1100000000000000:
            #The Inbound TE.
            
            pkt = packet.Packet(msg.data)
            protocols = self.get_protocols(pkt)
            p_eth = protocols['ethernet']
        
            if p_eth.ethertype == ether.ETH_TYPE_IPV6:
                p_ipv6 = protocols['ipv6']
                #self.logger.info("\L3= src:%s dst:%s proto:%s",p_ipv6.src,p_ipv6.dst, p_ipv6.nxt)
                
                if p_ipv6.nxt == 17:
                    p_udp = protocols['udp']
                    #self.logger.info("\L4= UDP src:%s dst:%s",p_udp.src_port,p_udp.dst_port)
                    trhLen= 5 + len(self.tlvStack)/8
                    
                    match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6, ipv6_src=p_ipv6.src, ipv6_dst=p_ipv6.dst, ip_proto=p_ipv6.nxt, udp_src=p_udp.src_port, udp_dst=p_udp.dst_port)
                    #Following will fail if a packet comes in before the full chain is deployed
                    actions.append(parser.OFPActionPushTrh(length=trhLen, nextuid=0x3b4d0100, tlvs=self.tlvStack))
                    actions.append(parser.OFPActionOutput(9, 2000))
                    self.add_flow(dp, 15, match, actions)
                    
                    #Send the packet that came to the controller back so it is outputted as well.
                    data = None
                    if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER:
                        data = msg.data
            
                    out = parser.OFPPacketOut(
                        datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                        actions=actions, data=data)
                    dp.send_msg(out)          
        
        
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

    def ipv4_to_int(self, ip_text):
        if ip_text == 0:
            return ip_text
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]      
        
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
        
