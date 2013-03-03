#!/usr/bin/env python
# -*- coding: utf-8 -*-
# generated by wxGlade 0.6.4 on Thu Feb 28 17:14:20 2013

import wx

# begin wxGlade: extracode
# end wxGlade





class MyDialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: MyDialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.panel_1 = wx.Panel(self, -1)
        self.label_1 = wx.StaticText(self, -1, "A capturar na ")
        self.gauge_1 = wx.Gauge(self, -1, 10, style=wx.GA_HORIZONTAL | wx.GA_SMOOTH)
        self.label_3 = wx.StaticText(self, -1, "Tempo")
        self.label_4 = wx.StaticText(self, -1, "Pacotes")
        self.panel_3 = wx.Panel(self, -1)
        self.panel_2 = wx.Panel(self, -1)
        self.button_1 = wx.Button(self, -1, "button_1")
        self.button_2 = wx.Button(self, -1, "button_2")
        self.panel_4 = wx.Panel(self, -1)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.SetTitle("dialog_1")
        self.SetSize((400, 300))
        self.label_1.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
        self.gauge_1.SetMinSize((300, 28))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_3 = wx.BoxSizer(wx.VERTICAL)
        sizer_4 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_5 = wx.BoxSizer(wx.VERTICAL)
        sizer_1.Add(self.panel_1, 1, wx.EXPAND, 0)
        sizer_1.Add(self.label_1, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_1.Add(self.gauge_1, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_5.Add(self.label_3, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_5.Add(self.label_4, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        sizer_2.Add(sizer_5, 1, wx.EXPAND, 0)
        sizer_3.Add(self.panel_3, 1, wx.EXPAND, 0)
        sizer_4.Add(self.panel_2, 1, wx.EXPAND, 0)
        sizer_4.Add(self.button_1, 0, 0, 0)
        sizer_4.Add(self.button_2, 0, 0, 0)
        sizer_4.Add(self.panel_4, 1, wx.EXPAND, 0)
        sizer_3.Add(sizer_4, 1, wx.EXPAND, 0)
        sizer_2.Add(sizer_3, 1, wx.EXPAND, 0)
        sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade

# end of class MyDialog
if __name__ == "__main__":
    app = wx.PySimpleApp(0)
    wx.InitAllImageHandlers()
    frame_1 = MyDialog(None, -1, "")
    app.SetTopWindow(frame_1)
    frame_1.Show()
    
    app.MainLoop()