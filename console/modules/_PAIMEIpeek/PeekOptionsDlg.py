#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PeekOptionsDlg.py 194 2007-04-05 15:31:53Z cameron $
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
import wx.lib.filebrowsebutton as filebrowse

class PeekOptionsDlg(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]
        # begin wxGlade: PeekOptionsDlg.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.log_static_staticbox = wx.StaticBox(self, -1, "Save log output to disk")
        self.boron_tag_static_staticbox = wx.StaticBox(self, -1, "Boron Tag")
        self.flags_static_staticbox = wx.StaticBox(self, -1, "Flags")
        self.quiet = wx.CheckBox(self, -1, "Disable run-time context dumps.")
        self.track_recv = wx.CheckBox(self, -1, "Enable recv() and recvfrom() hit logging.")
        self.log_file = filebrowse.FileBrowseButton(self, -1, labelText="", fileMask="*.txt", fileMode=wx.SAVE, toolTip="Specify the filename to save log output to")
        self.boron_tag = wx.TextCtrl(self, -1, "")
        self.ok = wx.Button(self, -1, "Ok")
        self.cancel = wx.Button(self, wx.ID_CANCEL)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        # event bindings.
        self.Bind(wx.EVT_BUTTON, self.on_button_ok, self.ok)

        # set default control values.
        self.boron_tag.SetValue(self.parent.boron_tag)
        self.log_file.SetValue(self.parent.log_file)
        self.quiet.SetValue(self.parent.quiet)
        self.track_recv.SetValue(self.parent.track_recv)


    def __set_properties(self):
        # begin wxGlade: PeekOptionsDlg.__set_properties
        self.SetTitle("Peek Options")
        self.track_recv.SetValue(1)
        self.ok.SetDefault()
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: PeekOptionsDlg.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        boron_tag_static = wx.StaticBoxSizer(self.boron_tag_static_staticbox, wx.HORIZONTAL)
        log_static = wx.StaticBoxSizer(self.log_static_staticbox, wx.HORIZONTAL)
        flags_static = wx.StaticBoxSizer(self.flags_static_staticbox, wx.HORIZONTAL)
        flags = wx.BoxSizer(wx.VERTICAL)
        flags.Add(self.quiet, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        flags.Add(self.track_recv, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        flags_static.Add(flags, 1, wx.EXPAND, 0)
        overall.Add(flags_static, 1, wx.EXPAND, 0)
        log_static.Add(self.log_file, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(log_static, 1, wx.EXPAND, 0)
        boron_tag_static.Add(self.boron_tag, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(boron_tag_static, 1, wx.EXPAND, 0)
        button_sizer.Add(self.ok, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_sizer.Add(self.cancel, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(button_sizer, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        self.Layout()
        # end wxGlade


    ####################################################################################################################
    def on_button_ok (self, event):
        '''
        Grab the form values and bubble them up to the parent module.
        '''

        self.parent.quiet      = self.quiet.GetValue()
        self.parent.track_recv = self.track_recv.GetValue()
        self.parent.log_file   = self.log_file.GetValue()
        self.parent.boron_tag  = self.boron_tag.GetLineText(0)

        self.Destroy()

