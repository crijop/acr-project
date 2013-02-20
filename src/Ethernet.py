'''
Created on 2013/02/20

@author: admin1
'''

class Ethernet(object):
    def __init__(self, macDst, macSrc, ipDst, ipSrc):
        self.macDst = macDst
        self.macSrc = macSrc
        self.ipDst = ipDst
        self.ipSrc = ipSrc
        pass
    
    def get_macDst(self):
            return self.macDst
            pass
    def get_macSrc(self):
        return self.macSrc
        pass
    def get_ipDst(self):
        return self.ipDst
        pass
    def get_ipSrc(self):
        return self.ipSrc
        pass
    
    pass
