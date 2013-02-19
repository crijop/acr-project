#-*- coding:utf-8 -*-
#!/usr/bin/python
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from pcapy import *
import datetime

#classe de Colorização
class bcolors:
    #BOLD = '\033[1m'
    #FUNDO PRETO = '\033[40m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m' + '\033[1m' + '\033[40m'
    OKGREEN = '\033[92m' + '\033[1m' + '\033[40m'
    WARNING = '\033[93m'
    FAIL = '\033[91m' + '\033[1m' + '\033[40m'
    ENDC = '\033[0m'
    
    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        pass
    pass


decoder = EthDecoder()

def callback(jdr, data):
    packet = decoder.decode(data)
    child = packet.child()
    if isinstance(child, IP):
        child = child.child()
        if isinstance(child, TCP):
            if child.get_th_dport() == 143 or child.get_th_dport() == 993:
                print 'IMAP'
                print dir(child)
                print child.get_data_as_string()
                print child.get_buffer_as_string()
                print child.get_bytes()

    pass


def testeCap(resposta):
    
    if resposta == "1":
        caminhoFile = raw_input("Introduza o caminho do ficheiro: (exemplo: /home/ficheiros/nomeFile.pcap): ")
        return caminhoFile
        pass
    elif resposta == "2":
        #list all devices
        devices = findalldevs()
        print devices
        
        #ask user to enter device name to sniff
        print "Available devices are :"
        for d in devices :
            print d
        
        dev = raw_input("Enter device name to sniff : ")
        
        print "Sniffing device " + dev
        return dev
        pass
    
    pass

#IMAP Port 143
#IMAP SSL Port 993
#IMAP StartTLS Port 143

def dialogoInicial():    
    print "Pretende fazer uma estatistica de um ficheiro pcap ou fazer uma captura?"
    print "Caso: ficheiro pcap  -> 1"
    print "Caso: fazer captura  -> 2"
    
    resposta = raw_input("Faça a sua escolha: ")
    return resposta
    pass

resposta = dialogoInicial()
while (resposta != "1" or resposta != "2"):
    #estatistica de um ficheiro pcap
    if resposta == "1":
        caminhoFile = testeCap(resposta)
        print bcolors.OKBLUE + "Estatisticas a efectuar no file: " + caminhoFile + "!" + bcolors.ENDC
        pcap = open_offline(caminhoFile)
        i = 0
        pcap.setfilter("tcp port 143 or tcp port 993")
        (header, payload) = pcap.next()
        while header:
            print ('%d -> %s: captured %d bytes, truncated to %d bytes'
                 %(i, datetime.datetime.now(), header.getlen(), header.getcaplen()))
            i +=1
            (header, payload) = pcap.next()
        break
        pass
    
    #estatistica de uma captura
    elif resposta == "2":
        print bcolors.OKGREEN + "Vai ser efecutada uma Captura, mas siga as instruções seguintes!" + bcolors.ENDC
        dev = testeCap(resposta)
        pcap = open_live(dev , 65536 , 1 , 0)
        pcap.loop(0, callback)
        
        pass
    else:
        print bcolors.FAIL + "A sua resposta não é válida, volte a responder!" + bcolors.ENDC
        resposta = dialogoInicial()
        pass
    pass
    