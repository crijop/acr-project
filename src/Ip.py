'''
Created on 2013/02/20

@author: admin1
'''

class Ip(object):
    def __init__(self, version, headerLength, timeToLive, protocoloIP, ipDst, ipSrc):
        self.version = version
        self.headerLength = headerLength
        self.timeToLive = timeToLive
        self.protocoloIP = protocoloIP
        self.ipDst = ipDst
        self.ipSrc = ipSrc
        pass
    
    def get_version(self):
        return self.version
        pass
    
    def get_headerLength(self):
        return self.headerLength
        pass
    
    def get_timeToLive(self):
        return self.timeToLive
        pass
    
    def get_protocoloIP(self):
        return self.protocoloIP
        pass
    
    def get_ipDst(self):
        return self.ipDst
        pass
    
    def get_ipSrc(self):
        return self.ipSrc
        pass
    
    pass