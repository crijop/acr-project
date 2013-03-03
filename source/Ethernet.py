'''
Created on 2013/02/20

@author: admin1
'''

class Ethernet(object):
    def __init__(self, macDst, macSrc, typeIP):
        self.macDst = macDst
        self.macSrc = macSrc
        self.typeIP = typeIP
        pass
    
    def get_macDst(self):
        return self.macDst
        pass
    
    def get_macSrc(self):
        return self.macSrc
        pass
    
    def get_typeIP(self):
        return self.typeIP
        pass
    
    
    pass
