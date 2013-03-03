#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Created on 2 de Mar de 2013

@author: xama
'''
import sys
import wx

# begin wxGlade: extracode
# end wxGlade

class Statistics(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: Statistics.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.notebook_1 = wx.Notebook(self, -1, style=0)
        self.panel_17 = wx.Panel(self.notebook_1, -1)
        self.panel_18 = wx.Panel(self.panel_17, -1)
        self.label_18 = wx.StaticText(self.panel_18, -1, "Filtro")
        self.imapLable = wx.StaticText(self.panel_18, -1, "IMAP - Porto 143")
        self.imapsLable = wx.StaticText(self.panel_18, -1, "IMAPS - Porto 993")
        self.static_line_9 = wx.StaticLine(self.panel_17, -1)
        self.panel_19 = wx.Panel(self.panel_17, -1)
        self.label_21 = wx.StaticText(self.panel_19, -1, "Tempo")
        self.firstPaketLable = wx.StaticText(self.panel_19, -1, "Primeiro Pacote:")
        self.lastPacketLable = wx.StaticText(self.panel_19, -1, "Ultimo Pacote:")
        self.eplisedTimeLable = wx.StaticText(self.panel_19, -1, "Tempo Decorrido:")
        self.static_line_10 = wx.StaticLine(self.panel_17, -1)
        self.panel_20 = wx.Panel(self.panel_17, -1)
        self.label_25 = wx.StaticText(self.panel_20, -1, "Em Exibição")
        self.fileNameLable = wx.StaticText(self.panel_20, -1, "Ficheiro")
        self.captureLengthLable = wx.StaticText(self.panel_20, -1, "Tamanho da Captura")
        self.packetNumberLable = wx.StaticText(self.panel_20, -1, "Numero de Pacotes")
        self.betweenPacketLable = wx.StaticText(self.panel_20, -1, "Entre o 1º e ultimo pacote:")
        self.medPLable = wx.StaticText(self.panel_20, -1, "Média Pacotes/Segundo")
        self.medLengthLable = wx.StaticText(self.panel_20, -1, "Média Tamanho")
        self.bytesLable = wx.StaticText(self.panel_20, -1, "Bytes")
        self.medByLable = wx.StaticText(self.panel_20, -1, "Média Bytes/Segundo")
        self.medMbLable = wx.StaticText(self.panel_20, -1, "Média Megabit/Segundo")
        #self.notebook_1_pane_2 = wx.Panel(self.notebook_1, -1)
        #self.notebook_2 = wx.Notebook(self.notebook_1_pane_2, -1, style=0)
        #self.notebook_2_pane_1 = wx.ScrolledWindow(self.notebook_2, -1, style=wx.TAB_TRAVERSAL)
        #self.ethernet_listCtrl = wx.ListCtrl(self.notebook_2_pane_1, -1, style=wx.LC_REPORT | wx.SUNKEN_BORDER)
        #self.notebook_2_pane_2 = wx.ScrolledWindow(self.notebook_2, -1, style=wx.TAB_TRAVERSAL)
        #self.ip_listCtrl = wx.ListCtrl(self.notebook_2_pane_2, -1, style=wx.LC_REPORT | wx.SUNKEN_BORDER)
        #self.notebook_2_pane_3 = wx.ScrolledWindow(self.notebook_2, -1, style=wx.TAB_TRAVERSAL)
        #self.tcp_listCtrl = wx.ListCtrl(self.notebook_2_pane_3, -1, style=wx.LC_REPORT | wx.SUNKEN_BORDER)
        self.notebook_1_pane_3 = wx.ScrolledWindow(self.notebook_1, -1, style=wx.TAB_TRAVERSAL)
        self.packetLength_listCtrl = wx.ListCtrl(self.notebook_1_pane_3, -1, style=wx.LC_REPORT | wx.SUNKEN_BORDER)
        self.panel_15 = wx.Panel(self, -1)
        self.button_1 = wx.Button(self, wx.ID_OK)
        
        self.Bind(wx.EVT_BUTTON, self.okThatsAll, self.button_1)
        
        self.panel_16 = wx.Panel(self, -1)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade
    
    def okThatsAll(self, event):
        
        self.Destroy()
        pass
    
    def __set_properties(self):
        # begin wxGlade: Statistics.__set_properties
        self.SetTitle("Estatisiticas Globais")
        self.SetSize((640, 480))
        self.label_18.SetFont(wx.Font(14, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        self.panel_18.SetMinSize((653, 70))
        self.label_21.SetFont(wx.Font(14, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        self.panel_19.SetMinSize((653, 100))
        self.label_25.SetFont(wx.Font(14, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        #self.notebook_2_pane_1.SetScrollRate(10, 10)
        #self.notebook_2_pane_2.SetScrollRate(10, 10)
        #self.notebook_2_pane_3.SetScrollRate(10, 10)
        self.notebook_1_pane_3.SetScrollRate(10, 10)
        self.notebook_1.SetMinSize((640, 420))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: Statistics.__do_layout
        sizer_7 = wx.BoxSizer(wx.VERTICAL)
        sizer_8 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_24 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_20 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_23 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_22 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_21 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_16 = wx.BoxSizer(wx.VERTICAL)
        sizer_19 = wx.BoxSizer(wx.VERTICAL)
        sizer_18 = wx.BoxSizer(wx.VERTICAL)
        sizer_17 = wx.BoxSizer(wx.VERTICAL)
        sizer_17.Add(self.label_18, 0, 0, 2)
        sizer_17.Add(self.imapLable, 0, wx.ALL, 2)
        sizer_17.Add(self.imapsLable, 0, wx.ALL, 2)
        self.panel_18.SetSizer(sizer_17)
        sizer_16.Add(self.panel_18, 0, wx.EXPAND, 0)
        sizer_16.Add(self.static_line_9, 0, wx.EXPAND, 0)
        sizer_18.Add(self.label_21, 0, 0, 0)
        sizer_18.Add(self.firstPaketLable, 0, wx.ALL, 2)
        sizer_18.Add(self.lastPacketLable, 0, wx.ALL, 2)
        sizer_18.Add(self.eplisedTimeLable, 0, wx.ALL, 2)
        self.panel_19.SetSizer(sizer_18)
        sizer_16.Add(self.panel_19, 0, wx.EXPAND, 0)
        sizer_16.Add(self.static_line_10, 0, wx.EXPAND, 0)
        sizer_19.Add(self.label_25, 0, 0, 0)
        sizer_19.Add(self.fileNameLable, 0, wx.ALL, 4)
        sizer_19.Add(self.captureLengthLable, 0, wx.ALL, 2)
        sizer_19.Add(self.packetNumberLable, 0, wx.ALL, 2)
        sizer_19.Add(self.betweenPacketLable, 0, wx.ALL, 2)
        sizer_19.Add(self.medPLable, 0, wx.ALL, 2)
        sizer_19.Add(self.medLengthLable, 0, wx.ALL, 2)
        sizer_19.Add(self.bytesLable, 0, wx.ALL, 2)
        sizer_19.Add(self.medByLable, 0, wx.ALL, 2)
        sizer_19.Add(self.medMbLable, 0, wx.ALL, 2)
        self.panel_20.SetSizer(sizer_19)
        sizer_16.Add(self.panel_20, 0, wx.EXPAND, 0)
        self.panel_17.SetSizer(sizer_16)
        #sizer_21.Add(self.ethernet_listCtrl, 1, wx.EXPAND, 0)
        #self.notebook_2_pane_1.SetSizer(sizer_21)
        #sizer_22.Add(self.ip_listCtrl, 1, wx.EXPAND, 0)
        #self.notebook_2_pane_2.SetSizer(sizer_22)
        #sizer_23.Add(self.tcp_listCtrl, 1, wx.EXPAND, 0)
        #self.notebook_2_pane_3.SetSizer(sizer_23)
        #self.notebook_2.AddPage(self.notebook_2_pane_1, "Ethernet")
        #self.notebook_2.AddPage(self.notebook_2_pane_2, "IPv4")
        #self.notebook_2.AddPage(self.notebook_2_pane_3, "TCP")
        #sizer_20.Add(self.notebook_2, 1, wx.EXPAND, 0)
        #self.notebook_1_pane_2.SetSizer(sizer_20)
        sizer_24.Add(self.packetLength_listCtrl, 1, wx.EXPAND, 0)
        self.notebook_1_pane_3.SetSizer(sizer_24)
        self.notebook_1.AddPage(self.panel_17, u"Sumário")
        #self.notebook_1.AddPage(self.notebook_1_pane_2, "EndPonts")
        self.notebook_1.AddPage(self.notebook_1_pane_3, "Tamanho dos Pacotes")
        sizer_7.Add(self.notebook_1, 12, wx.EXPAND, 0)
        sizer_8.Add(self.panel_15, 1, wx.EXPAND, 0)
        sizer_8.Add(self.button_1, 0, 0, 0)
        sizer_8.Add(self.panel_16, 1, wx.EXPAND, 0)
        sizer_7.Add(sizer_8, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_7)
        self.Layout()
        # end wxGlade
        
    def fieldTime(self, first, last, elapsed):
        
        self.firstPaketLable.SetLabel("Primeiro Pacote: " + str(first))
        self.lastPacketLable.SetLabel("Ultimo Pacote: " + str(last))
        self.eplisedTimeLable.SetLabel("Tempo Decorrido: " + str(elapsed))
        
        pass
        
    def fieldDisplay(self, infoList):
        
        self.fileNameLable.SetLabel("Nome do Ficheiro: " + infoList[0])
        self.captureLengthLable.SetLabel("Tamanho da Captura: " + str(infoList[1]) + " bytes")
        self.packetNumberLable.SetLabel("Numero de Pacotes: " + str(infoList[2]))
        self.betweenPacketLable.SetLabel("Entre o 1º e ultimo pacote: " + str(infoList[3]) + " sec")
        #print infoList[3]
        self.medPLable.SetLabel("Média Pacotes/Segundo: " + str(infoList[4]))
        
        self.medLengthLable.SetLabel("Média Tamanho: " + str(infoList[5]))
        
        self.bytesLable.SetLabel("Bytes: " + str(infoList[1]))
        self.medByLable.SetLabel("Média Bytes/Segundo: " + str(infoList[6]))
        self.medMbLable.SetLabel("Média Megabit/Segundo: " + str(infoList[7]))
    
        
        pass


    
    def fieldPacketLength(self, info):
        
         #Adiciona os cabeçalhos das colunas
        self.packetLength_listCtrl.InsertColumn(0, 'Item/Topico.', width=120)
        self.packetLength_listCtrl.InsertColumn(1, 'Numero', width=100)
        self.packetLength_listCtrl.InsertColumn(2, 'Precentagem', width=100)
        
        index = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "Tamanho Pacote")
        self.packetLength_listCtrl.SetStringItem(index, 1, str(info[0]))
        
        index1 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "0 - 19")
        
        self.packetLength_listCtrl.SetStringItem(index1, 1, str(info[1][0]))
        self.packetLength_listCtrl.SetStringItem(index1, 2, str(info[1][1]) + "%")
        
        index2 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "20  - 39")
        
        self.packetLength_listCtrl.SetStringItem(index2, 1, str(info[2][0]))
        self.packetLength_listCtrl.SetStringItem(index2, 2, str(info[2][1]) + "%")
        
        index3 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "40 - 79")
        
        self.packetLength_listCtrl.SetStringItem(index3, 1, str(info[3][0]))
        self.packetLength_listCtrl.SetStringItem(index3, 2, str(info[3][1]) + "%")
        
        index4 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "80  - 159")
        
        self.packetLength_listCtrl.SetStringItem(index4, 1, str(info[4][0]))
        self.packetLength_listCtrl.SetStringItem(index4, 2, str(info[4][1]) + "%")
        
        index5 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "160  - 319")
        
        self.packetLength_listCtrl.SetStringItem(index5, 1, str(info[5][0]))
        self.packetLength_listCtrl.SetStringItem(index5, 2, str(info[5][1]) + "%")
        
        index6 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "320 - 639")
        
        self.packetLength_listCtrl.SetStringItem(index6, 1, str(info[6][0]))
        self.packetLength_listCtrl.SetStringItem(index6, 2, str(info[6][1]) + "%")
        
        index4 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "640  - 1279")
        
        self.packetLength_listCtrl.SetStringItem(index4, 1, str(info[7][0]))
        self.packetLength_listCtrl.SetStringItem(index4, 2, str(info[7][1]) + "%")
        
        index5 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "1280  - 2559")
        
        self.packetLength_listCtrl.SetStringItem(index5, 1, str(info[8][0]))
        self.packetLength_listCtrl.SetStringItem(index5, 2, str(info[8][1]) + "%")
        
        index6 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "2560 - 5119")
        
        self.packetLength_listCtrl.SetStringItem(index6, 1, str(info[9][0]))
        self.packetLength_listCtrl.SetStringItem(index6, 2, str(info[9][1]) + "%")
        
        index7 = self.packetLength_listCtrl.InsertStringItem(sys.maxint, "5120  -")
        
        self.packetLength_listCtrl.SetStringItem(index7, 1, str(info[10][0]))
        self.packetLength_listCtrl.SetStringItem(index7, 2, str(info[10][1]) + "%")
       
       
   
        
        
        
        pass