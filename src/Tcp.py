'''
Created on 2013/02/20

@author: admin1
'''

class Tcp(object):
    def __init__(self, srcPort, dstPort, sequenceNumber, acknowledgement, tcpHeaderLength):
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgement = acknowledgement
        self.tcpHeaderLength = tcpHeaderLength
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
    
    pass