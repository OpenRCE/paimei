#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PyDbgDlg.py 194 2007-04-05 15:31:53Z cameron $
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

import _PAIMEIpeek

########################################################################################################################
class PyDbgDlg(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: PyDbgDialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.retrieve_list  = wx.Button(self, -1, "Retrieve List")
        self.process_list   = _PAIMEIpeek.ProcessListCtrl.ProcessListCtrl(self, -1, style=wx.LC_REPORT|wx.SUNKEN_BORDER, top=self.parent)
        self.load_target    = filebrowse.FileBrowseButton(self, -1, labelText="", fileMask="*.exe", fileMode=wx.OPEN, toolTip="Specify the target executable to load")
        self.attach_or_load = wx.Button(self, -1, "Attach / Load")
        self.cancel         = wx.Button(self, wx.ID_CANCEL)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        # event bindings.
        self.Bind(wx.EVT_BUTTON, self.process_list.on_retrieve_list, self.retrieve_list)
        self.Bind(wx.EVT_BUTTON, self.on_attach_or_load, self.attach_or_load)
        self.process_list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.process_list.on_select)


    ####################################################################################################################
    def __set_properties(self):
        # begin wxGlade: PyDbgDialog.__set_properties
        self.SetTitle("Select Target")
        self.SetSize((300, 500))
        self.retrieve_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.process_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.attach_or_load.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        # end wxGlade


    ####################################################################################################################
    def __do_layout(self):
        # begin wxGlade: PyDbgDialog.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        overall.Add(self.retrieve_list, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(self.process_list, 1, wx.EXPAND, 0)
        overall.Add(self.load_target, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_bar = wx.BoxSizer(wx.HORIZONTAL)
        button_bar.Add(self.attach_or_load, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_bar.Add(self.cancel, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(button_bar, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        self.Layout()
        # end wxGlade


    ####################################################################################################################
    def on_attach_or_load (self, event):
        '''
        Bubble up the attach or load target to the main PAIMEIpeek module.
        '''

        self.parent.load = self.load_target.GetValue()
        self.parent.pid  = self.process_list.selected_pid
        self.parent.proc = self.process_list.selected_proc
        
        if not self.parent.load and not self.parent.pid and not self.parent.proc:
            dlg = wx.MessageDialog(self, "You haven't selected a process to load or attach to.", "Error", wx.OK | wx.ICON_WARNING)
            dlg.ShowModal()
            return

        self.Destroy()