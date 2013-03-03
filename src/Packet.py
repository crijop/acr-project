'''
Created on 2013/02/20

@author: admin1
'''

class Packet(object):
        
    def __init__(self, length, nr,  protocolo, time, clEthernet, clIp, clTcp, cImap):
        self.length = length
        self.nr = nr
        self.protocolo = protocolo
        self.time = time
        self.clEthernet = clEthernet
        self.clIp = clIp
        self.clTcp = clTcp
        self.cImap = cImap
        pass
    
    def get_length(self):
        
        return self.length
        pass
    def get_nr(self):
        return self.nr
        pass
    
    def get_protocolo(self):
        return self.protocolo
        pass
    
    def get_time(self):
        return self.time
        pass
    
    def get_clEthernet(self):
        return self.clEthernet
        pass
    
    def get_clIp(self):
        return self.clIp
        pass
    
    def get_clTcp(self):
        return self.clTcp
        pass
    
    def get_cImap(self):
        return self.cImap
        pass
    
    