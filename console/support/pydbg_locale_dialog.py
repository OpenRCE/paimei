#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: pydbg_locale_dialog.py 210 2007-08-02 00:15:19Z pedram $
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

from pydbg import *

class pydbg_locale_dialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: pydbg_locale_dialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.pydbg_logo = wx.StaticBitmap(self, -1, wx.Bitmap(self.parent.cwd + "/images/pydbg.bmp", wx.BITMAP_TYPE_ANY))
        self.host_static = wx.StaticText(self, -1, "Host:")
        self.port_static = wx.StaticText(self, -1, "Port:")
        self.set_locale = wx.Button(self, -1, "Set Locale")

        # if the main_frame already contains pydbg locale values, use them.
        if self.parent.pydbg_host: self.host = wx.TextCtrl(self, -1, self.parent.pydbg_host)
        else:                      self.host = wx.TextCtrl(self, -1, "localhost")

        if self.parent.pydbg_port: self.port = wx.TextCtrl(self, -1, str(self.parent.pydbg_port))
        else:                      self.port = wx.TextCtrl(self, -1, "")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.on_set_locale, self.set_locale)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: pydbg_locale_dialog.__set_properties
        self.SetTitle("PyDbg Locale")
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.port_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.port.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.set_locale.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: pydbg_locale_dialog.__do_layout
        sizer_7 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_6 = wx.BoxSizer(wx.VERTICAL)
        pydbg_options = wx.GridSizer(2, 2, 0, 0)
        sizer_7.Add(self.pydbg_logo, 0, wx.ADJUST_MINSIZE, 0)
        sizer_7.Add((10, 20), 0, wx.ADJUST_MINSIZE, 0)
        pydbg_options.Add(self.host_static, 0, wx.ADJUST_MINSIZE, 0)
        pydbg_options.Add(self.host, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        pydbg_options.Add(self.port_static, 0, wx.ADJUST_MINSIZE, 0)
        pydbg_options.Add(self.port, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_6.Add(pydbg_options, 0, wx.EXPAND, 0)
        sizer_6.Add(self.set_locale, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_7.Add(sizer_6, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_7)
        sizer_7.Fit(self)
        sizer_7.SetSizeHints(self)
        self.Layout()
        self.Centre()
        # end wxGlade

    def on_set_locale(self, event): # wxGlade: pydbg_locale_dialog.<event_handler>
        try:
            host = self.host.GetLineText(0)
            port = int(self.port.GetLineText(0))
        except:
            pass

        # bubble up the form values to the main frame for possible persistent storage.
        self.parent.pydbg_host = host
        self.parent.pydbg_port = port

        self.pydbg_set_locale(host, port)
        self.Destroy()

    def pydbg_set_locale (self, host, port):
        if host not in ("localhost", "127.0.0.1") and type(port) is int:
            try:
                self.parent.pydbg = pydbg_client(host, port)
                self.parent.status_bar.SetStatusText("Successfully connected to PyDbg server on %s:%d" % (host, port))
                self.parent.status_bar.SetStatusText("PyDbg: %s" % host, 3)
            except:
                self.parent.status_bar.SetStatusText("Failed connecting to PyDbg server on %s:%d" % (host, port))
        else:
            self.parent.pydbg = pydbg()