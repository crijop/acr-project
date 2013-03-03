'''
Created on 2013/02/20

@author: admin1
'''

class Tcp(object):
    def __init__(self, srcPort, dstPort, sequenceNumber, acknowledgement, tcpHeaderLength, flags, wSizeValue, checksun):
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgement = acknowledgement
        self.tcpHeaderLength = tcpHeaderLength
        self.flags = flags
        self.wSizeValue = wSizeValue
        self.checksun = checksun
        
        pass
    
    class Flags(object):
        def __init__(self, ack, push, reset, syn, fin):
            self.ack = ack
            self.push = push
            self.reset = reset
            self.syn = syn
            self.fin = fin
            pass
        
        def get_ack(self):
            return self.ack
            pass
        
        def get_push(self):
            return self.push
            pass
        
        def get_reset(self):
            return self.reset
            pass
        
        def get_syn(self):
            return self.syn
            pass
        
        def get_fin(self):
            return self.fin
            pass
        
        pass
    
    def creatFlags(self, ack, push, reset, syn, fin):
        self.flagsFinal = Tcp.Flags(ack, push, reset, syn, fin)
        pass
    
    def get_srcPort(self):
        return self.srcPort
        pass
    
    def get_dstPort(self):
        return self.dstPort
        pass
    
    def get_sequenceNumber(self):
        return self.sequenceNumber
        pass
    
    def get_acknowledgement(self):
        return self.acknowledgement
        pass
    
    def get_tcpHeaderLength(self):
        return self.tcpHeaderLength
        pass
    
    def get_flags(self):
        return self.flags
        pass
    
    def get_wSizeValue(self):
        return self.wSizeValue
        pass
    
    def get_checksun(self):
        return self.checksun
        pass
    
    pass