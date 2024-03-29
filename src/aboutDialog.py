#!/usr/bin/env python
# -*- coding: utf-8 -*-
# generated by wxGlade 0.6.4 on Sun Mar  3 16:25:32 2013

import wx

# begin wxGlade: extracode
# end wxGlade


class AboutDialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: MyDialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.label_1 = wx.StaticText(self, -1, "Acerca")
        self.static_line_1 = wx.StaticLine(self, -1)
        self.label_2 = wx.StaticText(self, -1, u"O SniffImap é um programa que captura e analisa pacotes IMAP e IMAPs que circulam numa rede. Este programa foi desenvolvido no ambito da disciplina de Analise de Comunicações em Redes, do Mestrado em Engenharia de Segurança Informática. \n\nEste Programa fou desenvolvido por:\n\nAntónio Baião Nº 5604\nCarlos Palma Nº 5608\nDuarte Pereira Nº13215\n\nEscola Superior de Tecnologia e Gestão de Beja, Fevereiro , 2013")
        self.label_2.Wrap(400)
        self.panel_3 = wx.Panel(self, -1)
        self.button_1 = wx.Button(self, wx.ID_OK)
        self.panel_4 = wx.Panel(self, -1)

        self.Bind(wx.EVT_BUTTON, self.okThatsAll, self.button_1)
        
        self.__set_properties()
        self.__do_layout()
        # end wxGlade
    def okThatsAll(self, event):
        
        self.Destroy()
        pass
    
    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.SetTitle("Acerca")
        self.SetSize((400, 300))
        self.label_1.SetFont(wx.Font(14, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_1.Add(self.label_1, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_1.Add(self.static_line_1, 0, wx.EXPAND, 0)
        sizer_1.Add(self.label_2, 7, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_2.Add(self.panel_3, 1, wx.EXPAND, 0)
        sizer_2.Add(self.button_1, 0, 0, 0)
        sizer_2.Add(self.panel_4, 1, wx.EXPAND, 0)
        sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade