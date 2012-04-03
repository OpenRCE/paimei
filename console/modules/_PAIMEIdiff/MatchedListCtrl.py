#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: MatchedListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
import wx.lib.mixins.listctrl as listmix

import FunctionViewDifferDlg

sys.path.append("..")

import pida

class MatchedListCtrl (wx.ListCtrl, listmix.ListCtrlAutoWidthMixin, listmix.ColumnSorterMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES | wx.LC_SINGLE_SEL)
        self.top=top

        listmix.ListCtrlAutoWidthMixin.__init__(self)
        listmix.ColumnSorterMixin.__init__(self, 3)
        self.curr = -1
        
        self.itemDataMap = {}       
        
        self.InsertColumn(0,  "Function Name")
        self.InsertColumn(1,  "Start EA")
        self.InsertColumn(2,  "End EA")
        self.InsertColumn(3,  "Size")
        self.InsertColumn(4,  "Instruction Count")
        self.InsertColumn(5,  "BB Count")
        self.InsertColumn(6,  "Call Count")
        self.InsertColumn(7,  "Edge Count")
        self.InsertColumn(8,  "Match Method")
        self.InsertColumn(9,  "Match Value")
        self.Bind(wx.EVT_LIST_COL_CLICK, self.OnColClick)

    ####################################################################################################################
    def SortListItems(self, col=-1, ascending=1): 
        pass
    ####################################################################################################################    
    def OnColClick(self,event):
        event.Skip()  
          
    
    ####################################################################################################################
    def add_function(self, func, idx):
        '''
        Add a function the matched list box
        '''
        if idx == -1:
            idx = self.GetItemCount()
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
        self.SetStringItem(idx, 8, "%s" % func.ext["PAIMEIDiffFunction"].match_method)
        
        if "SPP" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "0x%08x" % func.ext["PAIMEIDiffFunction"].spp)
        elif "Smart MD5" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%s" % func.ext["PAIMEIDiffFunction"].smart_md5)
        elif "NECI" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%d:%d:%d:%d" % func.ext["PAIMEIDiffFunction"].neci)
        elif "Proximity" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "")
        elif "Name" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%s" % func.name)
        elif "API Call" == func.ext["PAIMEIDiffFunction"].match_method:
            call_str = ""
            for call in func.ext["PAIMEIDiffFunction"].refs_api:
                (ea,s) = call
                if call_str == "":
                    call_str += s
                else:
                    call_str += ":" + s
            self.SetStringItem(idx, 9, "%s" % call_str)
        elif "Constants" == func.ext["PAIMEIDiffFunction"].match_method:
            const_str = ""
            for const_s in func.ext["PAIMEIDiffFunction"].refs_constants:
                if const_str == "":
                    const_str += str(const_s)
                else:
                    const_str += ":" + str(const_s)
            self.SetStringItem(idx, 9, "%s" % const_str)
        elif "CRC" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "0x%08x" % func.ext["PAIMEIDiffFunction"].crc)
        elif "Stack Frame" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%d" % func.frame_size)
        elif "String References" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "")
        elif "Recursive Calls" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "")
        elif "Arg Var Size Count" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%d:%d:%d:%d" % (func.arg_size, func.num_args, func.local_var_size, func.num_local_vars )  )
        elif "Call To Call From" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "")
        elif "Size" == func.ext["PAIMEIDiffFunction"].match_method:
            self.SetStringItem(idx, 9, "%d" % func.ext["PAIMEIDiffFunction"].size)
        
        self.itemDataMap[func.ea_start] = func.ea_start
        self.SetItemData(idx, func.ea_start)
                       
        if func.ext["PAIMEIDiffFunction"].different:
            item = self.GetItem(idx)
            item.SetTextColour(wx.RED)
            self.SetItem(item)
            
        #self.function_list.append( func )
         
    ####################################################################################################################         
    def OnRightClick(self, event):
        item = self.GetItem(self.curr)
        if not hasattr(self, "popupID1"):
            self.popupID1 = wx.NewId()
            self.popupID2 = wx.NewId()
            self.popupID3 = wx.NewId()
            self.popupID4 = wx.NewId()

            self.Bind(wx.EVT_MENU, self.view_match_diff_functions, id=self.popupID1)
            self.Bind(wx.EVT_MENU, self.unmatch_functions, id=self.popupID2)
            self.Bind(wx.EVT_MENU, self.unmark_different, id=self.popupID3)
            self.Bind(wx.EVT_MENU, self.mark_different, id=self.popupID4)

           

        # make a menu
        menu = wx.Menu()
        # add some items
        menu.Append(self.popupID1, "View Matched/Diff Functions")
        menu.Append(self.popupID2, "Unmatch Functions")
        menu.Append(self.popupID3, "Unmark as Different")        
        menu.Append(self.popupID4, "Mark as Different")


        # Popup the menu.  If an item is selected then its handler
        # will be called before PopupMenu returns.
        self.PopupMenu(menu)
        menu.Destroy()
        
    ####################################################################################################################        
    def view_match_diff_functions(self, event):
        '''
        Display the matched/diffed functions dialog box
        '''
        dlg = FunctionViewDifferDlg.FunctionViewDifferDlg(parent=self.top)
        dlg.ShowModal()
        
    ####################################################################################################################
    def unmatch_functions(self, event):
        '''
        Unmatch selected function
        '''
        self.top.unmatch_function()

    ####################################################################################################################
    def mark_different(self, event):
        '''
        Mark selected function as different
        '''     
        item = self.top.MatchedBListCtrl.GetItem( self.top.MatchedAListCtrl.curr)
        item.SetTextColour(wx.RED)
        self.top.MatchedBListCtrl.SetItem(item)
        
        item = self.top.MatchedAListCtrl.GetItem( self.top.MatchedAListCtrl.curr)
        item.SetTextColour(wx.RED)
        self.top.MatchedAListCtrl.SetItem(item)
        
        self.top.matched_list.mark_function_as_different(self.top.MatchedAListCtrl.curr)
        


        
    ####################################################################################################################
    def unmark_different(self,event):
        '''
        Unmark selected function as different
        '''
        item = self.top.MatchedBListCtrl.GetItem( self.top.MatchedAListCtrl.curr)
        item.SetTextColour(wx.BLACK)
        self.top.MatchedBListCtrl.SetItem(item)
        
        item = self.top.MatchedAListCtrl.GetItem( self.top.MatchedAListCtrl.curr)
        item.SetTextColour(wx.BLACK)
        self.top.MatchedAListCtrl.SetItem(item)
        
        self.top.matched_list.unmark_function_as_different(self.top.MatchedAListCtrl.curr)
        

    ####################################################################################################################        
    def GetListCtrl(self):
        return self