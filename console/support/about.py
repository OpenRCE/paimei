#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: about.py 194 2007-04-05 15:31:53Z cameron $
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

class about(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]
        
        # begin wxGlade: about.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.about_logo = wx.StaticBitmap(self, -1, wx.Bitmap(self.parent.cwd + "/images/about.bmp", wx.BITMAP_TYPE_ANY))
        self.about = wx.TextCtrl(self, -1, "PaiMei Console\n\nCopyright 2006 Pedram Amini\n<pedram.amini@gmail.com>\n\nhttp://www.openrce.org", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_WORDWRAP)
        self.ok = wx.Button(self, -1, "Close")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.on_close, self.ok)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: about.__set_properties
        self.SetTitle("About PaiMei")
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.about.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.ok.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: about.__do_layout
        sizer_8 = wx.BoxSizer(wx.VERTICAL)
        sizer_8.Add(self.about_logo, 0, wx.ADJUST_MINSIZE, 0)
        sizer_8.Add(self.about, 5, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_8.Add(self.ok, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_8)
        sizer_8.Fit(self)
        sizer_8.SetSizeHints(self)
        self.Layout()
        self.Centre()
        # end wxGlade

    def on_close(self, event): # wxGlade: about.<event_handler>
        self.Destroy()


