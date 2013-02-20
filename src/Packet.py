'''
Created on 2013/02/20

@author: admin1
'''

class Packet(object):
        
    def __init__(self, nr,  protocolo, time):
        self.nr = nr
        self.protocolo = protocolo
        self.time = time
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