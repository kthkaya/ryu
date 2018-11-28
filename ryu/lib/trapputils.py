import array
from ryu.lib.packet import packet
from ryu.ofproto import ether


def get_protocols(pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols
    
def getTrid(msgData):
    pkt = packet.Packet(array.array('B', msgData))
    protocols = get_protocols(pkt)
    p_eth = protocols['ethernet']
    
    if p_eth.ethertype == ether.ETH_TYPE_IPV6:
        p_ipv6 = protocols['ipv6']
        #self.logger.info("\L3= src:%s dst:%s proto:%s",p_ipv6.src,p_ipv6.dst, p_ipv6.nxt)
        
        if p_ipv6.nxt == 17:
            p_udp = protocols['udp']
            #self.logger.info("\L4= UDP src:%s dst:%s",p_udp.src_port,p_udp.dst_port)
            return (p_ipv6.src,p_ipv6.dst,p_udp.src_port,p_udp.dst_port,p_ipv6.nxt)
    