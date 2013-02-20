#-*- coding:utf-8 -*-
#!/usr/bin/python

from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from interface_teste import MainMenu
from pcapy import *
from Packet import Packet
from struct import *
import datetime
import os
import socket
import wx

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

class SniffImap(object):
    
    decoder = EthDecoder()
    def __init__(self):
        
        self.listaPacotes = []
        
        app = wx.PySimpleApp(0)
        wx.InitAllImageHandlers()
        self.frame_1 = MainMenu(None, -1, "")
        app.SetTopWindow(self.frame_1)
        self.frame_1.Show()
        
        self.frame_1.openFileEvent(self.openCapture_file)
        
        #Começo da captura
        #resposta = self.dialogoInicial()
        #while (resposta != "1" or resposta != "2"):
            #estatistica de um ficheiro pcap
            #if resposta == "1":
                #caminhoFile = self.testeCap(resposta)
                #print bcolors.OKBLUE + "Estatisticas a efectuar no file: " + caminhoFile + "!" + bcolors.ENDC
            
            
        '''#estatistica de uma captura
        elif resposta == "2":
            print bcolors.OKGREEN + "Vai ser efecutada uma Captura, mas siga as instruções seguintes!" + bcolors.ENDC
            dev = self.testeCap(resposta)
            pcap = open_live(dev , 65536 , 1 , 0)
            pcap.loop(0, self.callback)
            
            pass
        else:
            print bcolors.FAIL + "A sua resposta não é válida, volte a responder!" + bcolors.ENDC
            resposta = self.dialogoInicial()
            pass
        pass'''
        app.MainLoop()
    
        
   
    def startCaptureSaved(self, caminhoFile):
            pcap = open_offline(caminhoFile)
            i = 1
            pcap.setfilter("tcp port 143 or tcp port 993")
            (header, packet) = pcap.next()
            while header:
                #print ('%d -> %s: captured %d bytes, truncated to %d bytes'
                #%(i, datetime.datetime.now(), header.getlen(), header.getcaplen()))
                     
                self.analisePacote(i, packet)
                #print lista
                #header.getlen() tamanho packert
                i +=1
                (header, packet) = pcap.next()
            
            self.frame_1.field_List_ctrl(self.listaPacotes)
            pass
        
    def callback(self, jdr, data):
        packet = self.decoder.decode(data)
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
    
    
    def testeCap(self, resposta):
        
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
    
    def dialogoInicial(self):    
        print "Pretende fazer uma estatistica de um ficheiro pcap ou fazer uma captura?"
        print "Caso: ficheiro pcap  -> 1"
        print "Caso: fazer captura  -> 2"
        
        resposta = raw_input("Faça a sua escolha: ")
        return resposta
        pass
    
    
    #Convert a string of 6 characters of ethernet address into a dash separated hex string
    def eth_addr (self, a) :
        b = "{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}".\
            format(ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b
    '''
    Analisar pacote
    '''
    def analisePacote(self,nr, packet):
        #parse ethernet header
        eth_length = 14
        
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        
        p = Packet(nr, str(eth_protocol), "time", "Ethernet", "IP", "TCP", "IMAP")
        
        
        self.listaPacotes.append(p)
        pass
    '''
    evento abrir captura a partir do ficheiro
    '''
    def openCapture_file(self, event):
        
        path = self.frame_1.onOpenFile()
        if path != None:
            self.frame_1.clearAllCaptures()
            self.startCaptureSaved(path)
    
if __name__ == "__main__":
    SniffImap()    
    
    