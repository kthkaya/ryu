from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.pack_utils import msg_pack_into
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet.ether_types import ETH_TYPE_IPV6
from ryu.ofproto import ofproto_v1_3
import struct


class Trapp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Trapp, self).__init__(*args, **kwargs)


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

        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        
        msg = ev.msg               # Object representing a packet_in data structure.
        dp = msg.datapath          # Switch Datapath ID
        ofproto = dp.ofproto       # OpenFlow Protocol version the entities negotiated. In our case OF1.3
        ofp_parser = dp.ofproto_parser 
        actions = []
        
        iport= 2
        oport = 3
        max_len = 2000
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        dst = eth.dst
        src = eth.src
        in_port = msg.match['in_port']
        
        self.logger.info("packet in %s %s %s %s", dp.id, src, dst, in_port)
        
        #Installing a flow rule
        #1. Create the match
        msg = ev.msg
        in_port = msg.match['in_port']
        # Get the destination ethernet address
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        
        match = ofp_parser.OFPMatch(in_port=iport, eth_type=ETH_TYPE_IPV6)
        #match = ofp_parser.OFPMatch(trh_nextuid=0x9f8e7d, eth_type=ETH_TYPE_IPV6)
        
        #2. Create the action
        #actions.append(ofp_parser.OFPActionSetTrhNextuid())
        #actions.append(ofp_parser.OFPActionPopTrh())
        tlvStack = self.packTLVs(6,0)
        actions.append(ofp_parser.OFPActionPushTrh(length=8, nextuid=0x3b4d0100, tlvs=tlvStack))
        actions.append(ofp_parser.OFPActionOutput(oport, max_len))
        
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        #3. Prepare FLOW_MOD message (match and action).
        mod = ofp_parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)

        #4. Send the message
        dp.send_msg(mod)
        
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
        
        