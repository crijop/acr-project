'''
Created on 11 de Mar de 2013

@author: xama
'''
import time
import wx
class RunningCaptureDialog(wx.Dialog):
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
        self.SetTitle("A Capturar...")
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
        pass

    def OnTimer(self, event):
        
        #self.gauge.SetValue(self.count)
        self.gauge_1.Pulse()
        timeToPrint = time.time() - self.incialTime
        self.label_3.SetLabel(str(time.strftime('%M:%S', time.localtime(timeToPrint))))
        #print timeToPrint
        self.label_3.Update()
        pass
    pass