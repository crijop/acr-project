#-*- coding:utf-8 -*-
#!/usr/bin/python

from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from pcapy import *
import datetime
import socket
from struct import *

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


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}".\
        format(ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
'''
Analisar pacote
'''
def analisePacote(packet):
    lista = []
    #parse ethernet header
    eth_length = 14
    
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    
    #Destination MAC,  Source MAC, Protocolo
    lista.append([eth_addr(packet[0:6]),eth_addr(packet[6:12]), str(eth_protocol)])
    return lista
    pass



resposta = dialogoInicial()
while (resposta != "1" or resposta != "2"):
    #estatistica de um ficheiro pcap
    if resposta == "1":
        caminhoFile = testeCap(resposta)
        print bcolors.OKBLUE + "Estatisticas a efectuar no file: " + caminhoFile + "!" + bcolors.ENDC
        pcap = open_offline(caminhoFile)
        i = 1
        pcap.setfilter("tcp port 143 or tcp port 993")
        (header, packet) = pcap.next()
        while header:
            #print ('%d -> %s: captured %d bytes, truncated to %d bytes'
            #%(i, datetime.datetime.now(), header.getlen(), header.getcaplen()))
                 
            lista = analisePacote(packet)
            print lista
            i +=1
            (header, packet) = pcap.next()
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
    