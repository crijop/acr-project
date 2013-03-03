#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on 3 de Mar de 2013

@author: xama
'''
# end of class MainMenu
from source.InterfaceGrafica import MainMenu
import wx


if __name__ == "__main__":
    app = wx.PySimpleApp(0)
    wx.InitAllImageHandlers()
    frame_1 = MainMenu(None, -1, "")
    app.SetTopWindow(frame_1)
    frame_1.Show()
    app.MainLoop()