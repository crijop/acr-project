#!/usr/bin/env python
# -*- coding: utf-8 -*-
# generated by wxGlade 0.6.4 on Wed Feb 20 15:25:01 2013


from gflags import TextWrap
from t import *
import os
import sys
import textwrap
import time
import wx
import wx.lib.agw.pyprogress as PP



# begin wxGlade: extracode
# end wxGlade

class CaptureDialog(wx.Dialog):
    def __init__(self, eventStop, interface, *args, **kwds):
        # begin wxGlade: CaptureDialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.incialTime = time.time()
        #print self.incialTime
        self.timer = wx.Timer(self, 1)
        self.Bind(wx.EVT_TIMER, self.OnTimer, self.timer)
        
        self.panel_1 = wx.Panel(self, -1)
        self.label_1 = wx.StaticText(self, -1, "A capturar na " + str(interface))
        self.gauge_1 = wx.Gauge(self, -1, 10, style=wx.GA_HORIZONTAL | wx.GA_SMOOTH)
        self.label_3 = wx.StaticText(self, -1, str(time.strftime('%H:%M:%S', time.localtime(time.time()))))
        #self.label_4 = wx.StaticText(self, -1, "Pacotes")
        self.panel_3 = wx.Panel(self, -1)
        self.panel_4 = wx.Panel(self, -1)
        self.button_2 = wx.Button(self, wx.ID_STOP)
        self.panel_5 = wx.Panel(self, -1)

        self.__set_properties()
        self.__do_layout()
        
        self.Bind(wx.EVT_BUTTON,eventStop, self.button_2)
        self.timer.Start(100)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: CaptureDialog.__set_properties
        self.SetTitle("dialog_1")
        self.SetSize((400, 300))
        self.label_1.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        self.gauge_1.SetMinSize((300, 28))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: CaptureDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_3 = wx.BoxSizer(wx.VERTICAL)
        sizer_4 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_5 = wx.BoxSizer(wx.VERTICAL)
        sizer_1.Add(self.panel_1, 1, wx.EXPAND, 0)
        sizer_1.Add(self.label_1, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_1.Add(self.gauge_1, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_5.Add(self.label_3, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        #sizer_5.Add(self.label_4, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_2.Add(sizer_5, 1, wx.EXPAND, 0)
        sizer_3.Add(self.panel_3, 1, wx.EXPAND, 0)
        sizer_4.Add(self.panel_4, 1, wx.EXPAND, 0)
        sizer_4.Add(self.button_2, 0, 0, 0)
        sizer_4.Add(self.panel_5, 1, wx.EXPAND, 0)
        sizer_3.Add(sizer_4, 1, wx.EXPAND, 0)
        sizer_2.Add(sizer_3, 1, wx.EXPAND, 0)
        sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade

    def OnTimer(self, event):
        
        #self.gauge.SetValue(self.count)
        self.gauge_1.Pulse()
        timeToPrint = time.time() - self.incialTime
        self.label_3.SetLabel(str(time.strftime('%M:%S', time.localtime(timeToPrint))))
        #print timeToPrint
        self.label_3.Update()
    
        #if self.count == 50:
            #self.timer.Stop()
            #self.text.SetLabel("Task Completed")
# end of class CaptureDialog
    
        pass
   

class MyDialog(wx.Dialog):
    def __init__(self, listInterfaces, *args, **kwds):
        # begin wxGlade: MyDialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.lableTitle = wx.StaticText(self, -1, "Escolha a interface que quer escutar:")
        self.toReturn = None
        self.listInterfaces = listInterfaces
        self.listRadioButtons = []
        
        self.button_1 = wx.Button(self, -1, "Cancelar")
        self.button_2 = wx.Button(self, -1, "OK")
        
        self.Bind(wx.EVT_BUTTON,self.onClose_Cancel, self.button_1)
        self.Bind(wx.EVT_BUTTON,self.getInterfaceChoiced, self.button_2)
        
        
        self.__set_properties()
        self.__do_layout()
        # end wxGlade
  
    def onClose_Cancel(self, event):
        self.toReturn = None
        self.Destroy()
        pass
    
     
    
    def getInterfaceChoiced(self, event):
        pos = 0
        
        for radio in self.listRadioButtons:
            if radio.GetValue() == True:
                pos = self.listRadioButtons.index(radio)
                self.toReturn = self.listInterfaces[pos]
                pass
            pass
        
        self.Destroy()
            
    def getValue(self):
        
        return self.toReturn
        
    pass
    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.SetTitle("dialog_1")
        self.SetSize((400, 300))
        self.lableTitle.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        # end wxGlade


    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_1.Add(self.lableTitle, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        
        for interface in self.listInterfaces:
            self.radio_btn_1 = wx.RadioButton(self, -1, str(interface))
            self.listRadioButtons.append(self.radio_btn_1)
            sizer_1.Add(self.radio_btn_1, 0, 0, 0)
        
        
        
        sizer_2.Add(self.button_1, 0, wx.ALIGN_BOTTOM | wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_2.Add(self.button_2, 0, wx.ALIGN_BOTTOM | wx.ALIGN_CENTER_HORIZONTAL | wx.ALIGN_CENTER_VERTICAL, 0)
        sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade
        
        
        
        


# end of class MyDialog


class MainMenu(wx.Frame):
    def __init__(self, *args, **kwds):
        # begin wxGlade: MainMenu.__init__
        kwds["style"] = wx.DEFAULT_FRAME_STYLE
        wx.Frame.__init__(self, *args, **kwds)
        
        self.interface = None
        
        # Menu Bar
        self.frame_1_menubar = wx.MenuBar()
        wxglade_tmp_menu = wx.Menu()
        self.newCaptura = wxglade_tmp_menu.Append(wx.NewId(), "Nova Captura", "", wx.ITEM_NORMAL)
        self.openCapture = wxglade_tmp_menu.Append(wx.NewId(), "Abrir Captura", "", wx.ITEM_NORMAL)
        self.saveCapture = wxglade_tmp_menu.Append(wx.NewId(), "Guardar Captura", "", wx.ITEM_NORMAL)
        #wxglade_tmp_menu.Append(wx.NewId(), "Guardar Captura Como...", "", wx.ITEM_NORMAL)
        self.sair = wxglade_tmp_menu.Append(wx.NewId(), "Sair", "", wx.ITEM_NORMAL)
        self.frame_1_menubar.Append(wxglade_tmp_menu, "Ficheiro")
        wxglade_tmp_menu = wx.Menu()
        self.frame_1_menubar.Append(wxglade_tmp_menu, "Estastisticas")
        self.statistics = wxglade_tmp_menu.Append(wx.NewId(), "Sumário Global", "", wx.ITEM_NORMAL)
        self.SetMenuBar(self.frame_1_menubar)
        
        '''capturaMenu = wx.Menu()
        self.frame_1_menubar.Append(capturaMenu, "Captura")
        self.SetMenuBar(self.frame_1_menubar)
        
        self.stopCaptura = capturaMenu.Append(wx.NewId(), "Parar Captura", "", wx.ITEM_NORMAL)
        '''
        
        # Menu Bar end
        self.window_2 = wx.SplitterWindow(self, -1, style=wx.SP_3D | wx.SP_BORDER)
        self.window_2_pane_1 = wx.ScrolledWindow(self.window_2, -1, style=wx.TAB_TRAVERSAL)
        self.list_ctrl = wx.ListCtrl(self.window_2_pane_1, -1, style=wx.LC_REPORT | wx.SUNKEN_BORDER)
        self.window_2_pane_2 = wx.Panel(self.window_2, -1)
        self.window_3 = wx.SplitterWindow(self.window_2_pane_2, -1, style=wx.SP_3D | wx.SP_BORDER)
        self.window_3_pane_1 = wx.ScrolledWindow(self.window_3, -1, style=wx.TAB_TRAVERSAL)
        self.tree_ctrl = wx.TreeCtrl(self.window_3_pane_1, -1, style=wx.TR_HAS_BUTTONS | wx.TR_DEFAULT_STYLE | wx.SUNKEN_BORDER | wx.TR_HIDE_ROOT)
        self.window_3_pane_2 = wx.ScrolledWindow(self.window_3, -1, style=wx.TAB_TRAVERSAL)
        self.buffer_Lable = wx.StaticText(self.window_3_pane_2, -1, "label_2")
        self.frame_1_statusbar = self.CreateStatusBar(1, 0)




        self.Bind(wx.EVT_TREE_ITEM_EXPANDED, self.expandItemTree_Event, self.tree_ctrl)
        self.Bind(wx.EVT_TREE_ITEM_COLLAPSED, self.colapsItemTree_Event, self.tree_ctrl)
        self.__set_properties()
        self.__do_layout()
        # end wxGlade
        self.pakets = []
        
        self.sniff_controller = SniffImap(self)
        self.buffer_Lable.SetLabel("To a espera")
        
    def add_packet(self, packet):
        
        self.pakets.append(packet)
        print "tamanho", len(self.pakets)
        pass
    
    def get_allpackets(self):
        print "tamanho", len(self.pakets)
        return self.pakets
        pass
        


    def printTeste(self):
        print "to a funcionar"
        pass
    
    def __set_properties(self):
        # begin wxGlade: MainMenu.__set_properties
        self.SetTitle("SniffIMAP")
        self.SetSize((800, 715))
        self.window_2_pane_1.SetScrollRate(10, 10)
        self.window_3_pane_1.SetScrollRate(10, 10)
        self.window_3_pane_2.SetScrollRate(10, 10)
        self.frame_1_statusbar.SetStatusWidths([-1])
        # statusbar fields
        frame_1_statusbar_fields = ["frame_1_statusbar"]
        for i in range(len(frame_1_statusbar_fields)):
            self.frame_1_statusbar.SetStatusText(frame_1_statusbar_fields[i], i)
        # end wxGlade


    def __do_layout(self):
        # begin wxGlade: MainMenu.__do_layout
        sizer_6 = wx.BoxSizer(wx.VERTICAL)
        sizer_7 = wx.BoxSizer(wx.VERTICAL)
        sizer_10 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_9 = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer_8 = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer_8.Add(self.list_ctrl, 1, wx.EXPAND, 0)
        
        
        #Adiciona os cabeçalhos das colunas
        self.list_ctrl.InsertColumn(0, 'No.', width=50)
        self.list_ctrl.InsertColumn(1, 'Tempo', width=150)
        self.list_ctrl.InsertColumn(2, 'Origem', width=125)
        self.list_ctrl.InsertColumn(3, 'Destino', width=125)
        self.list_ctrl.InsertColumn(4, 'Protocolo', width=125)
        self.list_ctrl.InsertColumn(5, 'Dimensão', width=125)
        self.list_ctrl.InsertColumn(6, 'Mac Origen', width=125)
        self.list_ctrl.InsertColumn(7, 'Mac Destino', width=125)
        
             
        
        self.window_2_pane_1.SetSizer(self.sizer_8)
        sizer_9.Add(self.tree_ctrl, 1, wx.EXPAND, 0)
        self.window_3_pane_1.SetSizer(sizer_9)
        sizer_10.Add(self.buffer_Lable, 0, 0, 0)
        self.window_3_pane_2.SetSizer(sizer_10)
        self.window_3.SplitHorizontally(self.window_3_pane_1, self.window_3_pane_2)
        sizer_7.Add(self.window_3, 1, wx.EXPAND, 0)
        self.window_2_pane_2.SetSizer(sizer_7)
        self.window_2.SplitHorizontally(self.window_2_pane_1, self.window_2_pane_2)
        sizer_6.Add(self.window_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_6)
        self.Layout()
        # end wxGlade


    def field_lineOfList_ctrl(self, i,  item):
        #print "To na linha"
        
        index = self.list_ctrl.InsertStringItem(sys.maxint, str(item.get_nr()))
        self.list_ctrl.SetStringItem(index, 1, str(item.get_time()))
        self.list_ctrl.SetStringItem(index, 2, str(item.get_clIp().get_ipSrc()))
        self.list_ctrl.SetStringItem(index, 3, str(item.get_clIp().get_ipDst()))
        self.list_ctrl.SetStringItem(index, 4, str(item.get_clEthernet().get_macSrc()))
        self.list_ctrl.SetStringItem(index, 5, str(item.get_clEthernet()))
        self.list_ctrl.SetStringItem(index, 6, str(item.get_clEthernet()))
        
        
        
        #self.list_ctrl.SetStringItem(count, 4, item.get_clIp())
        #self.list_ctrl.SetStringItem(count, 5, item.get_clTcp())
        #self.list_ctrl.SetStringItem(count, 6, item.get_cImap())
        
        if index % 2:
            self.list_ctrl.SetItemBackgroundColour(index, "white")
        else:
            self.list_ctrl.SetItemBackgroundColour(index, "#9ce9ef")
        #index += 1


        self.list_ctrl.UpdateWindowUI()
        self.Show()
            
        
        #self.buffer_Lable.SetLabel("Teste" + str(item.get_nr()))
        #self.buffer_Lable.Update()
       
        
                                     
        #print "Cheguei no fim"
        #self.Update()
        #self.list_ctrl.Update()
        #self.sizer_8.Show()
        #self.list_ctrl.UpdateWindowUI()
        
        #self.list_ctrl.Refresh()
        
        #self.Show()
        
        pass


    def field_List_ctrl(self,  list):
        count = 0
        
        for item in list:
            
            self.list_ctrl.InsertStringItem(count, str(item.get_nr()))
            self.list_ctrl.SetStringItem(count, 1, str(item.get_time()))
            self.list_ctrl.SetStringItem(count, 2, str(item.get_clIp().get_ipSrc()))
            self.list_ctrl.SetStringItem(count, 3, str(item.get_clIp().get_ipDst()))
            
            if str(item.get_clTcp().get_srcPort()) == "143"  or str(item.get_clTcp().get_dstPort()) == "143":
            
                self.list_ctrl.SetStringItem(count, 4, "IMAP")
                
            elif str(item.get_clTcp().get_srcPort()) == "993"  or str(item.get_clTcp().get_dstPort()) == "993":
                
                self.list_ctrl.SetStringItem(count, 4, "IMAPS")
                
                pass
                
            self.list_ctrl.SetStringItem(count, 5, str(item.get_clEthernet()))
            self.list_ctrl.SetStringItem(count, 6, str(item.get_clEthernet().get_macSrc()))
            self.list_ctrl.SetStringItem(count, 7, str(item.get_clEthernet().get_macDst()))
            
            
            
            #self.list_ctrl.SetStringItem(count, 4, item.get_clIp())
            #self.list_ctrl.SetStringItem(count, 5, item.get_clTcp())
            #self.list_ctrl.SetStringItem(count, 6, item.get_cImap())
            
            if count % 2:
                self.list_ctrl.SetItemBackgroundColour(count, "white")
            else:
                self.list_ctrl.SetItemBackgroundColour(count, "#9ce9ef")
            #index += 1


            self.list_ctrl.UpdateWindowUI()
            self.Show()
            count += 1
                
          
            
        
        pass
    
    def openFileEvent(self, event):
        
        self.Bind(wx.EVT_MENU, event, self.openCapture)
        
        pass
    
    def saveFileEvent(self, event):
        
        self.Bind(wx.EVT_MENU, event, self.saveCapture)
        
        pass
    def packetList_Selected_event(self, event):
        
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, event, self.list_ctrl)
        
        pass
    
    def statistics_event(self, event):
    
        self.Bind(wx.EVT_MENU, event, self.statistics)
        pass
    
    def newCaptura_event(self, event):
        self.Bind(wx.EVT_MENU, event, self.newCaptura)
        pass
    
    def sair_event(self, event):
        
        self.Bind(wx.EVT_CLOSE, event, self)
        self.Bind(wx.EVT_MENU, event, self.sair)
        
        pass
    
    def stopCaptura_event(self, event):
        
        self.event = event
        
        pass
    
    def onOpenFile(self):
        self.currentDirectory = os.getcwd()
        filePath = None
        """
        Create and show the Open FileDialog
        """
        dlg = wx.FileDialog(
            self, message="Choose a file",
            defaultDir=self.currentDirectory, 
            defaultFile="",
            wildcard="*.pcap",
            style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
            )
        if dlg.ShowModal() == wx.ID_OK:
            paths = dlg.GetPaths()
            #print "You chose the following file(s):"
            for path in paths:
                filePath = path
        dlg.Destroy()
        
        return filePath
    
    def onSaveFile(self):
        self.currentDirectory = os.getcwd()
        filePath = None
        
        dlg = wx.FileDialog(
            self, message="Save file as ...", 
            defaultDir=self.currentDirectory, 
            defaultFile="", wildcard="*.pcap", style=wx.SAVE
            )
        if dlg.ShowModal() == wx.ID_OK:
            filePath = dlg.GetPath()
            print "You chose the following filename: %s" % filePath
        dlg.Destroy()
        
        return filePath
        pass
    
    def clearAllCaptures(self):
        print "APAGAR TUDO"
        self.list_ctrl.DeleteAllItems()
        self.Show()
        self.list_ctrl.UpdateWindowUI()
        
    '''
    Coosntroi a arvore com a informação presente na captura
    '''    
    def makeTree(self, packetInfo):
        
       
        self.tree_ctrl.DeleteAllItems()
        root = self.tree_ctrl.AddRoot('Root')


        packet = self.tree_ctrl.AppendItem(root, "Pacote", -1,-1, None)   
        
        
        self.tree_ctrl.AppendItem(packet, 'Numero do Pacote: ' + str(packetInfo.get_nr()), -1,-1, None)
        self.tree_ctrl.AppendItem(packet, 'Tamanho do Pacote: ' + str(packetInfo.get_nr()), -1,-1, None)
        self.tree_ctrl.AppendItem(packet, 'Chegada do Pacote: ' + str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packetInfo.get_time())))), -1,-1, None)
        
        ethernet = self.tree_ctrl.AppendItem(root, 'Ethernet', -1,-1, None)
        
        
        ethernetInfo = packetInfo.get_clEthernet()
        
        self.tree_ctrl.AppendItem(ethernet, 'Mac de Destino: ' + str(ethernetInfo.get_macDst()), -1,-1, None)
        self.tree_ctrl.AppendItem(ethernet, 'Mac de Origem: ' + str(ethernetInfo.get_macSrc()), -1,-1, None)
        self.tree_ctrl.AppendItem(ethernet, 'Tipo: IP ' + str(ethernetInfo.get_typeIP()) + ' (0x0' + str(ethernetInfo.get_typeIP()) + '00)', -1,-1, None)
        
        ip = self.tree_ctrl.AppendItem(root, 'Protocolo Internet (IP)', -1,-1, None)
        
        ipInfo = packetInfo.get_clIp()
        
        self.tree_ctrl.AppendItem(ip, 'Versão: ' + str(ipInfo.get_version()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Tamanho do Cabeçalho: ' + str(ipInfo.get_headerLength()) + ' bytes', -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Tamanho Total: ' + str(ipInfo.get_totalLengh()) + ' bytes', -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Identificação: ' + str(ipInfo.get_identification()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Flags: ' + str(ipInfo.get_flags()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Tempo de Vida: ' + str(ipInfo.get_timeToLive()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Protocolo IP: ' + str(ipInfo.get_protocoloIP()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'Cabeçalho Checksum: ' + str(ipInfo.get_headerChecksum()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'IP de Destino: ' + str(ipInfo.get_ipDst()), -1,-1, None)
        self.tree_ctrl.AppendItem(ip, 'IP de Origem: ' + str(ipInfo.get_ipSrc()), -1,-1, None)
        
        tcp = self.tree_ctrl.AppendItem(root, 'Protocolo de Controlo de Transmissão (TCP)', -1,-1, None)
        tcpInfo = packetInfo.get_clTcp()
        
        self.tree_ctrl.AppendItem(tcp, 'Porta de Origem: ' + str(tcpInfo.get_srcPort()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Porta de Destino: ' + str(tcpInfo.get_dstPort()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Número de Sequencia: ' + str(tcpInfo.get_sequenceNumber()) + ' bytes', -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Reconhecimento: ' + str(tcpInfo.get_acknowledgement()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Total Cabeçalho: ' + str(tcpInfo.get_tcpHeaderLength()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Flags: ' + str(tcpInfo.get_flags()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Tamanho da Janela: ' + str(tcpInfo.get_wSizeValue()), -1,-1, None)
        self.tree_ctrl.AppendItem(tcp, 'Checksum: ' + str(tcpInfo.get_checksun()), -1,-1, None)
        
        
        
        imap = self.tree_ctrl.AppendItem(root, 'Protocolo de Acesso a Mensagens de Internet (IMAP)', -1,-1, None)
        
        imapInfo = packetInfo.get_cImap()
        #buffer =  '\n'.join(textwrap.wrap('buffer: ' + imapInfo.get_buffer_Imap(), 120))
        buffer = self.manualWrap(imapInfo.get_buffer_Imap(),80)
        
        #print buffer
        
        count = 0
       
        for line in buffer:
            if count == 0:
                self.tree_ctrl.AppendItem(imap, "buffer: " + line, -1,-1, None)
                count = 1
            else:
                self.tree_ctrl.AppendItem(imap, line, -1,-1, None)
                pass
            pass
            
    
        self.buffer_Lable.SetLabel('\n'.join(textwrap.wrap(imapInfo.get_buffer_Imap(), 80)))
        
        
        #self.tree_ctrl.Expand(packet)
      
        self.tree_ctrl.UpdateWindowUI()
        self.window_3_pane_2.Update()
        self.Refresh()
        self.Show()
        '''for method in failsList:
            
            classe = wx.TreeItemData()
            classe.SetData(method)
            
            #metodo.
            for test in method.getTestList():
                data = wx.TreeItemData()
                data.SetData(test)
                no = self.tree.AppendItem(metodo, '' + "<"+str(test.getLineNumber())+"> " + str(test.getName()), -1, -1, data)
                '''
    def manualWrap(self, buffer, width):
        listWraped = []
        wrap = ""
        
        count = 0
        for x in buffer:
            
            wrap += x
            
            if count == width:
                count = 0
                #print wrap
                listWraped.append(wrap)
                wrap = ""
                wrap += x
                
            count += 1
            pass
            
        
        return listWraped
    
    pass
    def expandItemTree_Event(self, event):
        
        item = event.GetItem()
        
        print self.tree_ctrl.GetItemText(item)
        
        self.tree_ctrl.Update()
        pass
        
    def colapsItemTree_Event(self, event):
        
        
        pass
    def changeStatusBarInfo(self, nr, time):
        
        self.frame_1_statusbar.SetStatusText("Número de pacotes: " + str(nr) + " Tempo da captura: " + str(time))
        self.Show()
        pass
    
    def onLive(self, listInterfaces):
        
        self.selectInterface = MyDialog(listInterfaces, None, -1, "")
        #self.selectInterface.__do_layout(listInterfaces)
        self.selectInterface.ShowModal()
        self.selectInterface.Destroy()
        
        self.interface= self.selectInterface.getValue()
        if(self.interface == None):
            
            self.frame_1_statusbar.SetStatusText("Concluido ")
        else:
            self.frame_1_statusbar.SetStatusText("A Capturar . . . ")
            '''style = wx.PD_APP_MODAL|wx.PD_ELAPSED_TIME|wx.PD_CAN_ABORT
            dlg = PP.PyProgress(None, -1, "A Capturar . . .",
                            "A capturar pacotes na " + str(self.interface),                            
                            style)
            
            
            keepGoing = True
            
     
            while keepGoing:
               
                wx.MilliSleep(30)
     
                keepGoing = dlg.UpdatePulse()
     
            dlg.Destroy()
            wx.SafeYield()
            wx.GetApp().GetTopWindow().Raise()
            
            print "AQUIII"'''
        self.Show()
        
        return self.interface
        pass
    
    def get_interfaceChoiced(self):
        
        return self.interface
    pass
    def forceExit(self):
        
        self.Destroy()
        sys.exit(0)
        
        pass
    
    def stopCaptureAction(self):
        pass
    
# end of class MainMenu
if __name__ == "__main__":
    app = wx.PySimpleApp(0)
    wx.InitAllImageHandlers()
    frame_1 = MainMenu(None, -1, "")
    app.SetTopWindow(frame_1)
    frame_1.Show()
    app.MainLoop()