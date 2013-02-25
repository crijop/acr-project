'''
Created on 2013/02/20

@author: admin1
'''

class Ip(object):
    def __init__(self, version, headerLength, totalLengh, identification, flags, timeToLive, protocoloIP, headerChecksum, ipDst, ipSrc):
        self.version = version
        self.headerLength = headerLength
        self.totalLengh = totalLengh
        self.identification = identification
        self.flags = flags
        self.timeToLive = timeToLive
        self.protocoloIP = protocoloIP
        self.headerChecksum = headerChecksum
        self.ipDst = ipDst
        self.ipSrc = ipSrc
        pass
    
    def get_version(self):
        return self.version
        pass
    
    def get_headerLength(self):
        return 4 * int(self.headerLength)
        pass
    
    def get_totalLengh(self):
        return self.totalLengh
        pass
    
    def get_identification(self):
        return self.identification
        pass
    
    def get_flags(self):
        return self.flags
        pass
    
    def get_timeToLive(self):
        return self.timeToLive
        pass
    
    def get_protocoloIP(self):
        return self.protocoloIP
        pass
    
    def get_headerChecksum(self):
        return self.headerChecksum
        pass
    
    def get_ipDst(self):
        return self.ipDst
        pass
    
    def get_ipSrc(self):
        return self.ipSrc
        pass
    
    pass