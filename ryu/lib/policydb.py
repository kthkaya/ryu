import ipaddress

class PolicyDB(object):

    def __init__(self,chainPol):
        self.db={}
        #Can be i_port -> out_port, in_vlan ->out_vlan sequences, or a TRH
        self.chainPol = chainPol
       
    def populate(self, nrOfKeys):  
        baseIP = 0x20012001200120010000000000000001 
        dstIP="64:ff9b::c0a8:205"
        srcDstPort=1234
        proto = 17
        
        for x in range(0,nrOfKeys):
            srcIP= ipaddress.IPv6Address(baseIP)
            trid = (str(srcIP),dstIP,srcDstPort,srcDstPort,proto)
            self.add(trid)
            baseIP+=1
    
    #Warning! Doesn't check key uniqueness
    def add(self, trid):
        self.db[trid] = self.chainPol
    
    def find(self, trid): 
        #Return the value mapped to the trid
        try:
            return self.db[trid]
        except KeyError as e:
            print ("Policy not found for TRID - %s" % str(e))