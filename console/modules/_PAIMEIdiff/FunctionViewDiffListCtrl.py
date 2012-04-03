#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: FunctionViewDiffListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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

class FunctionViewDiffListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None,dlg=None,ctrl=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES | wx.LC_SINGLE_SEL )
        self.top=top
        self.dlg=dlg
        self.parent = parent
        self.ctrl_name = ctrl
        self.curr = 0

        ListCtrlAutoWidthMixin.__init__(self)

        self.InsertColumn(0, ctrl + ": EA")
        self.InsertColumn(1, ctrl + ": Mnem")
        self.InsertColumn(2, ctrl + ": Op 1")
        self.InsertColumn(3, ctrl + ": Op 2")
        self.InsertColumn(4, ctrl + ": Matched")
        self.InsertColumn(5, ctrl + ": Match Method")
        self.InsertColumn(6, ctrl + ": Match Value")
        self.InsertColumn(7, ctrl + ": Basic Block EA")

        
        self.load_function()
    
    ####################################################################################################################
    def load_function(self, man_func=None):
        '''
        load function into the list ctrl
        '''
        if man_func != None:
            func = man_func
        elif self.ctrl_name == "A":
            function = self.top.matched_list.matched_functions[ self.top.MatchedAListCtrl.curr ]
            (func,func_b) = function
            self.dlg.function_a.append(func)
            self.dlg.function_a_current+=1
           
        elif self.ctrl_name == "B":
            function = self.top.matched_list.matched_functions[ self.top.MatchedBListCtrl.curr ]
            (func_a,func) = function
            self.dlg.function_b.append(func)
            self.dlg.function_b_current+=1
           
        self.DeleteAllItems()
        i = 0
        spacer = 0
        idx = 0
        max_num = func.num_instructions + len(func.nodes.values())
        
        while i <= max_num:
            self.InsertStringItem(idx, "")
            self.SetStringItem(idx, 0, "")
            self.SetStringItem(idx, 1, "")
            self.SetStringItem(idx, 2, "")
            self.SetStringItem(idx, 3, "")
            self.SetStringItem(idx, 4, "")
            self.SetStringItem(idx, 5, "")
            self.SetStringItem(idx, 6, "")
            self.SetStringItem(idx, 7, "")
            self.SetStringItem(idx, 8, "")
            self.SetStringItem(idx, 9, "")
            self.SetStringItem(idx, 10, "")
            self.SetStringItem(idx, 11, "")
            self.SetStringItem(idx, 12, "")
            self.SetStringItem(idx, 13, "")
            self.SetStringItem(idx, 14, "")
            self.SetStringItem(idx, 15, "")
            i+=1
        i = 0
        idx = 0
        bb_count = 0
        for bb in func.sorted_nodes():
            for ii in bb.sorted_instructions():
                self.SetStringItem(idx, 0, "0x%08x" % ii.ea)
                self.SetStringItem(idx, 1, "%s" % ii.mnem)
                self.SetStringItem(idx, 2, "%s" % ii.op1)
                self.SetStringItem(idx, 3, "%s" % ii.op2)
                if bb.ext["PAIMEIDiffBasicBlock"].matched:
                    self.SetStringItem(idx, 4, "Yes")
                    self.SetStringItem(idx, 5, "%s" % bb.ext["PAIMEIDiffBasicBlock"].match_method)
                    if bb.ext["PAIMEIDiffBasicBlock"].match_method == "SPP":
                        self.SetStringItem(idx, 6, "0x%08x" % bb.ext["PAIMEIDiffBasicBlock"].spp)
                    elif bb.ext["PAIMEIDiffBasicBlock"].match_method == "NECI":
                        pass
                    elif bb.ext["PAIMEIDiffBasicBlock"].match_method == "API":
                        call_str = ""
                        for call in func.ext["PAIMEIDiffFunction"].refs_api:
                            (ea,c) = call
                            if call_str == "":
                                call_str += c
                            else:
                                call_str += ":" + c
                        self.SetStringItem(idx, 6, "%s" % call_str)
                    elif bb.ext["PAIMEIDiffBasicBlock"].match_method == "Constants":
                        const_str = ""
                        for const_s in bb.ext["PAIMEIDiffBasicBlock"].refs_constants:
                            if const_str == "":
                                const_str += str(const_s)
                            else:
                                const_str += ":" + str(const_s)
                        self.SetStringItem(idx, 6, "%s" % const_str)   
                else:
                    self.SetStringItem(idx, 4, "No")
                    self.SetStringItem(idx, 5, "")
                
                self.SetStringItem(idx, 7, "0x%08x" % bb.ea_start)
                if bb.ext["PAIMEIDiffBasicBlock"].ignore:
                    item = self.GetItem(idx)
                    item.SetTextColour(wx.LIGHT_GREY)
                    self.SetItem(item)
                elif not bb.ext["PAIMEIDiffBasicBlock"].matched:
                    item = self.GetItem(idx)
                    item.SetTextColour(wx.RED)
                    self.SetItem(item)
                idx+=1
            idx+=1

    ####################################################################################################################       
    def OnItemSelect(self,evt):
        self.curr = evt.m_itemIndex
        if self.ctrl_name == "A":
            if self.curr < self.dlg.FunctionViewBDiffListCtrl.GetItemCount():
                self.dlg.FunctionViewBDiffListCtrl.curr = self.curr
                item = self.dlg.FunctionViewBDiffListCtrl.GetItem(self.curr)
                item.m_stateMask = wx.LIST_STATE_SELECTED  
                item.m_state     = wx.LIST_STATE_SELECTED  
                self.dlg.FunctionViewBDiffListCtrl.SetItem(item)
                self.dlg.FunctionViewBDiffListCtrl.EnsureVisible(self.curr)
        else:
            if self.curr < self.dlg.FunctionViewADiffListCtrl.GetItemCount():
                self.dlg.FunctionViewADiffListCtrl.curr = self.curr
                item = self.dlg.FunctionViewADiffListCtrl.GetItem(self.curr)
                item.m_stateMask = wx.LIST_STATE_SELECTED  
                item.m_state     = wx.LIST_STATE_SELECTED  
                self.dlg.FunctionViewADiffListCtrl.SetItem(item)
                self.dlg.FunctionViewADiffListCtrl.EnsureVisible(self.curr)
        
        
    
    
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

    ####################################################################################################################        
    def view_basic_block(self, event):
        #self.curr = event.m_itemIndex
        
        item = self.GetItem(self.curr, 7)
            
        bb = item.GetText()
        
        if len(bb) == 0:
            return

        if self.ctrl_name == "A":
            self.dlg.FunctionViewStatsAListCtrl.load_basic_block_stats(bb)
        else:
            self.dlg.FunctionViewStatsBListCtrl.load_basic_block_stats(bb)
    
    ####################################################################################################################
    def view_function(self,event):
        if self.ctrl_name == "A":
            self.dlg.FunctionViewStatsAListCtrl.load_function_stats()
        else:
            self.dlg.FunctionViewStatsBListCtrl.load_function_stats()
            
    ####################################################################################################################
    def OnDoubleClick(self,event):
        item = self.GetItem(self.curr, 1)
        mnem = item.GetText()
        if mnem == "call":
            item = self.GetItem(self.curr, 2)
            dest = item.GetText()
            i = 0
            while i < len(self.top.matched_list.matched_functions):
                func_a, func_b = self.top.matched_list.matched_functions[i]
                if self.ctrl_name == "A":
                    func = func_a
                elif self.ctrl_name == "B":
                    func = func_b
                if func.name == dest:
                    self.load_function(func)
                    break
                i+=1