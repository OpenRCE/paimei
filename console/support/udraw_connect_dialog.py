#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: udraw_connect_dialog.py 194 2007-04-05 15:31:53Z cameron $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import wx
import sys

sys.path.append("..")

import utils

class udraw_connect_dialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: udraw_connect_dialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.udraw_logo = wx.StaticBitmap(self, -1, wx.Bitmap(self.parent.cwd + "/images/udraw.bmp", wx.BITMAP_TYPE_ANY))
        self.host_static = wx.StaticText(self, -1, "Host:")
        self.port_static = wx.StaticText(self, -1, "Port:")
        self.connect = wx.Button(self, -1, "Connect")

        # if the main_frame already contains udraw values, use them.
        if self.parent.udraw_host: self.host = wx.TextCtrl(self, -1, self.parent.udraw_host)
        else:                      self.host = wx.TextCtrl(self, -1, "127.0.0.1")

        if self.parent.udraw_port: self.port = wx.TextCtrl(self, -1, str(self.parent.udraw_port))
        else:                      self.port = wx.TextCtrl(self, -1, "2542")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.on_connect, self.connect)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: udraw_connect_dialog.__set_properties
        self.SetTitle("uDraw(Graph) Connect")
        self.host_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.port_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.port.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.connect.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.connect.SetDefault()
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: udraw_connect_dialog.__do_layout
        sizer_7_copy = wx.BoxSizer(wx.HORIZONTAL)
        sizer_6_copy = wx.BoxSizer(wx.VERTICAL)
        udraw_options = wx.GridSizer(2, 2, 0, 0)
        sizer_7_copy.Add(self.udraw_logo, 0, wx.ADJUST_MINSIZE, 0)
        sizer_7_copy.Add((10, 20), 0, wx.ADJUST_MINSIZE, 0)
        udraw_options.Add(self.host_static, 0, wx.ADJUST_MINSIZE, 0)
        udraw_options.Add(self.host, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        udraw_options.Add(self.port_static, 0, wx.ADJUST_MINSIZE, 0)
        udraw_options.Add(self.port, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_6_copy.Add(udraw_options, 0, wx.EXPAND, 0)
        sizer_6_copy.Add(self.connect, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_7_copy.Add(sizer_6_copy, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_7_copy)
        sizer_7_copy.Fit(self)
        sizer_7_copy.SetSizeHints(self)
        self.Layout()
        # end wxGlade

    def on_connect(self, event): # wxGlade: udraw_connect_dialog.<event_handler>
        try:
            host = self.host.GetLineText(0)
            port = int(self.port.GetLineText(0))
        except:
            self.parent.status_bar.SetStatusText("Invalid hostname / port combination")
            self.Destroy()
            return

        # bubble up the form values to the main frame for possible persistent storage.
        self.parent.udraw_host = host
        self.parent.udraw_port = port

        self.udraw_connect(host, port)
        self.Destroy()

    def udraw_connect (self, host, port):
        try:
            self.parent.udraw = utils.udraw_connector(host, port)
        except:
            self.parent.status_bar.SetStatusText("Failed connecting to uDraw(Graph) server.")
            return

        self.parent.status_bar.SetStatusText("Successfully connected to uDraw(Graph) server at %s." % host)
        self.parent.status_bar.SetStatusText("uDraw: %s" % host, 4)