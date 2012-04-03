#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: UnmatchedListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
@author:       Peter Silberman
@license:      GNU General Public License 2.0 or later
@contact:      peter.silberman@gmail.com
@organization: www.openrce.org
'''

import wx
import os
import sys
import time

from wx.lib.mixins.listctrl import ColumnSorterMixin
from wx.lib.mixins.listctrl import ListCtrlAutoWidthMixin

import FunctionViewDlg

sys.path.append("..")


import pida

class UnmatchedListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES | wx.LC_SINGLE_SEL)
        self.top=top
        
        ListCtrlAutoWidthMixin.__init__(self)
        
        self.curr = -1
        
        self.function_list = []

        self.InsertColumn(0,  "Function Name")
        self.InsertColumn(1,  "Start EA")
        self.InsertColumn(2,  "End EA")
        self.InsertColumn(3,  "Size")
        self.InsertColumn(4,  "Instruction Count")
        self.InsertColumn(5,  "BB Count")
        self.InsertColumn(6,  "Call Count")
        self.InsertColumn(7,  "Edge Count")

    ####################################################################################################################
    def OnRightClick(self, event):
        if not hasattr(self, "popupID1"):
            self.popupID1 = wx.NewId()
            self.popupID2 = wx.NewId()
    

            self.Bind(wx.EVT_MENU, self.match_function, id=self.popupID1)
            self.Bind(wx.EVT_MENU, self.view_function, id=self.popupID2)
  

        # make a menu
        menu = wx.Menu()
        # add some items
        menu.Append(self.popupID1, "Manually Match Function")
        menu.Append(self.popupID2, "View Function")
 

        # Popup the menu.  If an item is selected then its handler
        # will be called before PopupMenu returns.
        self.PopupMenu(menu)
        menu.Destroy()

    ####################################################################################################################
    def add_function(self, func, idx):
        '''
        Add function to list ctrl
        '''
        if idx == -1:
            idx = self.GetItemCount()
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "%s" % func.name)
        self.SetStringItem(idx, 1, "0x%08x" % func.ea_start)
        self.SetStringItem(idx, 2, "0x%08x" % func.ea_end)
        self.SetStringItem(idx, 3, "%d" % func.ext["PAIMEIDiffFunction"].size)
        self.SetStringItem(idx, 4, "%d" % func.num_instructions)
        self.SetStringItem(idx, 5, "%d" % len(func.nodes))
        self.SetStringItem(idx, 6, "%d" % func.ext["PAIMEIDiffFunction"].num_calls)
        self.SetStringItem(idx, 7, "%d" % 1)
        self.function_list.append( func )
    
    ####################################################################################################################
    def match_function(self, event):
        '''
        match the function manually
        '''
        self.top.manual_match_function()
        
    ####################################################################################################################
    def view_function(self,event):
        dlg = FunctionViewDlg.FunctionViewDlg(parent=self)
        dlg.ShowModal()
        