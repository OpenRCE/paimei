#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: mysql_connect_dialog.py 194 2007-04-05 15:31:53Z cameron $
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
import MySQLdb

class mysql_connect_dialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: mysql_connect_dialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.mysql_logo = wx.StaticBitmap(self, -1, wx.Bitmap(self.parent.cwd + "/images/mysql.bmp", wx.BITMAP_TYPE_ANY))
        self.host_static = wx.StaticText(self, -1, "MySQL Host:")
        self.username_static = wx.StaticText(self, -1, "MySQL User:")
        self.password_static = wx.StaticText(self, -1, "MySQL Passwd:")
        self.connect = wx.Button(self, -1, "Connect")

        # if the main frame already contains mysql values, then use them.
        if self.parent.mysql_host:     self.host = wx.TextCtrl(self, -1, self.parent.mysql_host)
        else:                          self.host = wx.TextCtrl(self, -1, "localhost")

        if self.parent.mysql_username: self.username = wx.TextCtrl(self, -1, self.parent.mysql_username)
        else:                          self.username = wx.TextCtrl(self, -1, "root")

        if self.parent.mysql_password: self.password = wx.TextCtrl(self, -1, self.parent.mysql_password, style=wx.TE_PASSWORD)
        else:                          self.password = wx.TextCtrl(self, -1, "", style=wx.TE_PASSWORD)

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.on_connect, self.connect)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: mysql_connect_dialog.__set_properties
        self.SetTitle("MySQL Connect")
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.username_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.username.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.password_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.password.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.connect.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.connect.SetDefault()
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: mysql_connect_dialog.__do_layout
        sizer_4 = wx.BoxSizer(wx.VERTICAL)
        sizer_5 = wx.BoxSizer(wx.HORIZONTAL)
        mysql_options = wx.GridSizer(3, 2, 0, 0)
        sizer_5.Add(self.mysql_logo, 0, wx.ADJUST_MINSIZE, 0)
        sizer_5.Add((10, 20), 0, wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.host_static, 0, wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.host, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.username_static, 0, wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.username, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.password_static, 0, wx.ADJUST_MINSIZE, 0)
        mysql_options.Add(self.password, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_5.Add(mysql_options, 0, wx.EXPAND, 0)
        sizer_4.Add(sizer_5, 1, wx.EXPAND, 0)
        sizer_4.Add(self.connect, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_4)
        sizer_4.Fit(self)
        sizer_4.SetSizeHints(self)
        self.Layout()
        self.Centre()
        # end wxGlade

    def on_connect(self, event): # wxGlade: mysql_connect_dialog.<event_handler>
        host     = self.host.GetLineText(0)
        username = self.username.GetLineText(0)
        password = self.password.GetLineText(0)

        # bubble up the form values to the main frame for possible persistent storage.
        self.parent.mysql_host     = host
        self.parent.mysql_username = username
        self.parent.mysql_password = password

        self.mysql_connect(host, username, password)
        self.Destroy()

    def mysql_connect (self, host, username, password):
        try:
            self.parent.mysql = MySQLdb.connect(host=host, user=username, passwd=password, db="paimei")
        except MySQLdb.OperationalError, err:
            self.parent.status_bar.SetStatusText("Failed connecting to MySQL server: %s" % err[1])
            return

        self.parent.status_bar.SetStatusText("Successfully connected to MySQL server at %s." % host)
        self.parent.status_bar.SetStatusText("MySQL: %s" % host, 2)