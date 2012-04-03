#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: FunctionViewListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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



sys.path.append("..")

import pida

class FunctionViewListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES | wx.LC_SINGLE_SEL)
        self.top=top
        self.parent = parent
        self.curr = 0
        ListCtrlAutoWidthMixin.__init__(self)
        self.InsertColumn(0,  "EA")
        self.InsertColumn(1,  "Mnem")
        self.InsertColumn(2,  "Op 1")
        self.InsertColumn(3,  "Op 2")
        self.load_function()

    def load_function(self):
        func = self.top.function_list[ self.top.curr ]
        idx = 0
        for bb in func.sorted_nodes():
            for inst in bb.sorted_instructions():
                self.InsertStringItem(idx, "")
                self.SetStringItem(idx, 0, "0x%08x" % inst.ea)            
                self.SetStringItem(idx, 1, "%s" % inst.mnem)
                self.SetStringItem(idx, 2, "%s" % inst.op1)
                self.SetStringItem(idx, 3, "%s" % inst.op2)
                idx+=1
            self.InsertStringItem(idx, "")
            self.SetStringItem(idx, 0, "")            
            self.SetStringItem(idx, 1, "")
            self.SetStringItem(idx, 2, "")
            self.SetStringItem(idx, 3, "")
            idx+=1

    ####################################################################################################################
    def OnRightClick(self, event):
        if not hasattr(self, "popupID1"):
            self.popupID1 = wx.NewId()
            self.popupID2 = wx.NewId()
    

            self.Bind(wx.EVT_MENU, self.view_basic_block, id=self.popupID1)
            self.Bind(wx.EVT_MENU, self.view_function, id=self.popupID2)
  

        # make a menu
        menu = wx.Menu()
        # add some items
        menu.Append(self.popupID1, "View Basic Block Stats")
        menu.Append(self.popupID2, "View Function Stats")
 

        # Popup the menu.  If an item is selected then its handler
        # will be called before PopupMenu returns.
        self.PopupMenu(menu)
        menu.Destroy()
        
    def view_basic_block(self, event):
        #self.curr = event.m_itemIndex
        item = self.GetItem(self.curr, 0)
        bb = item.GetText()
        print bb
        if len(bb) == 0:
            return
        self.parent.FunctionViewStatsListCtrl.load_basic_block_stats(bb)
    
    def view_function(self,event):
        self.parent.FunctionViewStatsListCtrl.load_function_stats()
    
    def OnItemSelect(self,evt):
        self.curr = evt.m_itemIndex
        if self.curr <= self.GetItemCount():
            self.curr = self.curr
            item = self.GetItem(self.curr)
            item.m_stateMask = wx.LIST_STATE_SELECTED  
            item.m_state     = wx.LIST_STATE_SELECTED  
            self.SetItem(item)
            self.EnsureVisible(self.curr)

