#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: ProcessListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
import copy

from wx.lib.mixins.listctrl import ColumnSorterMixin
from wx.lib.mixins.listctrl import ListCtrlAutoWidthMixin

from pydbg import *
import utils

class ProcessListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin, ColumnSorterMixin):
    '''
    Our custom list control containing a sortable list of PIDs and process names.
    '''

    FUNCTIONS    = utils.process_stalker.FUNCTIONS
    BASIC_BLOCKS = utils.process_stalker.BASIC_BLOCKS

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES )
        self.top                 = top
        self.selected_pid        = 0
        self.selected_proc       = None

        ListCtrlAutoWidthMixin.__init__(self)

        self.items_sort_map = {}
        self.itemDataMap    = self.items_sort_map

        ColumnSorterMixin.__init__(self, 2)

        self.InsertColumn(0, "PID")
        self.InsertColumn(1, "Process")


    ####################################################################################################################
    def GetListCtrl (self):
        '''
        Used by the ColumnSorterMixin, see wx/lib/mixins/listctrl.py
        '''

        return self


    ####################################################################################################################
    def on_retrieve_list (self, event):
        pydbg = self.top.main_frame.pydbg

        self.DeleteAllItems()

        idx = 0
        for (pid, proc) in pydbg.enumerate_processes():
            # ignore system processes.
            if pid < 10:
                continue

            self.InsertStringItem(idx, "")
            self.SetStringItem(idx, 0, "%d" % pid)
            self.SetStringItem(idx, 1, proc)

            self.items_sort_map[idx] = (pid, proc)
            self.SetItemData(idx, idx)

            idx += 1


    ####################################################################################################################
    def on_select (self, event):
        '''
        '''

        self.selected_pid  = int(self.GetItem(event.m_itemIndex, 0).GetText())
        self.selected_proc =     self.GetItem(event.m_itemIndex, 1).GetText()