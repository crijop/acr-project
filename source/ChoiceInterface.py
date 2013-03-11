'''
Created on 11 de Mar de 2013

@author: xama
'''
# begin wxGlade: extracode
# end wxGlade
import wx

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
        self.SetTitle("Escolher Interface")
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