#-*- coding:utf-8 -*-
#!/usr/bin/python

from Ethernet import *
from Ip import *
from Packet import Packet
from Tcp import *
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from interface_teste import MainMenu
from pcapy import *
from struct import *
from threading import Thread
import datetime
import os
import socket
import time
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
        self.stopCature = False
        
        app = wx.PySimpleApp(0)
        wx.InitAllImageHandlers()
        self.frame_1 = MainMenu(None, -1, "")
        app.SetTopWindow(self.frame_1)
        self.frame_1.Show()
        
        self.frame_1.openFileEvent(self.openCapture_file)
        self.frame_1.packetList_Selected_event(self.selectPacketEvent)
        self.frame_1.sair_event(self.exitProgram)
        self.frame_1.newCaptura_event(self.newCapturaEvent)
        self.frame_1.stopCaptura_event(self.stopCaturaEvent)
        
        
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
        pass
    
    def interfaceRede(self):
        interface = findalldevs()
        return interface
        pass
    
    def startCapture(self):
        #interface = self.interfaceRede()
        '''
        for d in  interface:
            print d
            pass        
        '''
        '''
        Arranjar maneira de passar o valor da interface que o utilizador devolver para 
        meter na variavel interface....
        '''
        interface = "eth0"
        
        print "vou começar a escutar a rede"
        pcap = open_live(interface , 65536 , 1 , 0)
        i = 1
        
        #pcap.setfilter("tcp port 143 or tcp port 993")
        (header, packet) = pcap.next()
        while header:
            '''Analisar pacote'''
            
            print "OLAAAA ", i
            self.anasilePacoteNewCaptura(i, packet)
            
            i +=1
            (header, packet) = pcap.next()
            
            if self.stopCature == True:
                break
            pass
        print "Acabei de escutar"
        #pcap.loop(0, self.callback)
        pass
    
    
    def startCaptureSaved(self, caminhoFile):
        pcap = open_offline(caminhoFile)
        i = 1
        
        pcap.setfilter("tcp port 143 or tcp port 993")
        (header, packet) = pcap.next()
        while header:
            #print ('%d -> %s: captured %d bytes, truncated to %d bytes'
            #%(i, datetime.datetime.now(), header.getlen(), header.getcaplen()))
            floatTime = str(header.getts()[0]) + "." + str(header.getts()[1])
            
            #print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(floatTime)))  
            self.analisePacote(i, packet, float(floatTime))
            #print lista
            #header.getlen() tamanho packert
            i +=1
            (header, packet) = pcap.next()
        self.frame_1.changeStatusBarInfo(i - 1)
        self.frame_1.field_List_ctrl(self.listaPacotes)
        pass
    
    def anasilePacoteNewCaptura(self, i, packet):
        #################################################
        #ETHERNET HEADER  
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        macDst = self.eth_addr(packet[0:6])
        macSrc = self.eth_addr(packet[6:12])
        eth_protocol = socket.ntohs(eth[2])
        #################################################
        
        #################################################
        #Protocolo IP HEADER  
        ip_header = packet[eth_length:20+eth_length]
        #print ip_header
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        # >> retirar quatro bits ao final
        version = version_ihl >> 4
        headerLenght = version_ihl & 0xF
        
        #headerLenght = headerLenght * 4 #bytes
        totalLengh = iph[2]
        identification = iph[3]
        flagsIP = iph[4]
        iph_length = headerLenght * 4
        timeToLive = iph[5]
        protocol = iph[6]
        headerChecksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        ipDst = str(d_addr)
        ipSrc = str(s_addr)
        #################################################
        
        #################################################
        #Protocolo TPC HEADER        
        t = iph_length + eth_length
        tcp_header = packet[t:t+20]
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        srcPort = tcph[0]
        dstPort = tcph[1]
        sequenceNumber = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcpHeaderLength = doff_reserved >> 4
        flagsTcp = tcph[5]
        wSizeValue = tcph[6]
        checksun = tcph[7]
        #################################################
        
        #################################################
        #Protocolo IMAP HEADER
        
        #################################################
        
        #Protocolo Ethernet
        ethernet = Ethernet(macDst, macSrc, eth_protocol)
        
        #Protocolo IP
        ip = Ip(str(version), str(headerLenght), str(totalLengh), str(identification), str(flagsIP), str(timeToLive), str(protocol), str(headerChecksum), ipDst, ipSrc)
        
        #Protocolo TCP
        tcp = Tcp(str(srcPort), str(dstPort), str(sequenceNumber), str(acknowledgement), str(tcpHeaderLength), flagsTcp, wSizeValue, checksun)
        
        #Pacote
        p = Packet("", str(eth_protocol), "", ethernet, ip, tcp, "IMAP")
        
        self.frame_1.field_lineOfList_ctrl(i, p)
        self.listaPacotes.append(p)
        
        pass
    
    
        
    def callback(self, jdr, data):
        packet = self.decoder.decode(data)
        child = packet.child()
        if isinstance(child, IP):
            child = child.child()
            if isinstance(child, TCP):
                #if child.get_th_dport() == 143 or child.get_th_dport() == 993:
                print 'IMAP'
                    #===========================================================
                    # print dir(child)
                    # print child.get_data_as_string()
                    # print child.get_buffer_as_string()
                    # print child.get_bytes()
                    #===========================================================
    
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
    def analisePacote(self,nr, packet, epoch_time):
        
        #################################################
        #ETHERNET HEADER  
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        macDst = self.eth_addr(packet[0:6])
        macSrc = self.eth_addr(packet[6:12])
        eth_protocol = socket.ntohs(eth[2])
        #################################################
        
        #################################################
        #Protocolo IP HEADER  
        ip_header = packet[eth_length:20+eth_length]
        #print ip_header
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        # >> retirar quatro bits ao final
        version = version_ihl >> 4
        headerLenght = version_ihl & 0xF
        
        #headerLenght = headerLenght * 4 #bytes
        totalLengh = iph[2]
        identification = iph[3]
        flagsIP = iph[4]
        iph_length = headerLenght * 4
        timeToLive = iph[5]
        protocol = iph[6]
        headerChecksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        ipDst = str(d_addr)
        ipSrc = str(s_addr)
        #################################################
        
        #################################################
        #Protocolo TPC HEADER        
        t = iph_length + eth_length
        tcp_header = packet[t:t+20]
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        srcPort = tcph[0]
        dstPort = tcph[1]
        sequenceNumber = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcpHeaderLength = doff_reserved >> 4
        flagsTcp = tcph[5]
        wSizeValue = tcph[6]
        checksun = tcph[7]
        #################################################
        
        #################################################
        #Protocolo IMAP HEADER
        
        #################################################
        
        #Protocolo Ethernet
        ethernet = Ethernet(macDst, macSrc, eth_protocol)
        
        #Protocolo IP
        ip = Ip(str(version), str(headerLenght), str(totalLengh), str(identification), str(flagsIP), str(timeToLive), str(protocol), str(headerChecksum), ipDst, ipSrc)
        
        #Protocolo TCP
        tcp = Tcp(str(srcPort), str(dstPort), str(sequenceNumber), str(acknowledgement), str(tcpHeaderLength), flagsTcp, wSizeValue, checksun)
        
        #Pacote
        p = Packet(nr, str(eth_protocol), epoch_time, ethernet, ip, tcp, "IMAP")


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
            
    def selectPacketEvent(self, event):
        currentItem = event.m_itemIndex
        
        
        self.frame_1.makeTree(self.listaPacotes[int(currentItem)])
        
        pass
    
    '''
    Trata do envento de saida do programa
    '''    
    def exitProgram(self, event):  # wxGlade: PyUnitiABCP.<event_handler>
        if wx.MessageBox("Deseja sair do programa?", "Confirmar", wx.YES_NO) == wx.YES :
            #print "sair"
            exit(0)
            pass
        pass
    
    def newCapturaEvent(self, event):
        self.t = Thread(target=self.startCapture, args=())
        self.t.start()
    
        pass
    
    def stopCaturaEvent(self, event):
        
        self.stopCature = True
    
        
    
if __name__ == "__main__":
    SniffImap()    
    
    