#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: FunctionViewStatsListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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

class FunctionViewStatsListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None, name=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES )
        self.top=top
        self.name_ctrl = name
        self.parent = parent

        ListCtrlAutoWidthMixin.__init__(self)

        self.InsertColumn(0,  "Field")
        self.InsertColumn(1,  "Value")

    ####################################################################################################################        
    def load_function_stats(self):
        '''
        load the function stats like signatures name extra
        '''
        self.DeleteAllItems()
        idx = 0
        if self.name_ctrl == "A":
            function = self.top.matched_list.matched_functions[ self.top.MatchedAListCtrl.curr ]
            (func,func_b) = function
        elif self.name_ctrl == "B":
            function = self.top.matched_list.matched_functions[ self.top.MatchedBListCtrl.curr ]
            (func_a,func) = function
        else:
            func = self.parent.parent.function_list[ self.parent.parent.curr]
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Name")
        self.SetStringItem(idx, 1, "%s" % func.name)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "EA Start")
        self.SetStringItem(idx, 1, "0x%08x" % func.ea_start)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "EA End")
        self.SetStringItem(idx, 1, "0x%08x" % func.ea_end)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Instruction Count")
        self.SetStringItem(idx, 1, "%d" % func.num_instructions)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "BB Count")
        self.SetStringItem(idx, 1, "%d" % len(func.nodes.values()))
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Call Count")
        self.SetStringItem(idx, 1, "%d" % func.ext["PAIMEIDiffFunction"].num_calls)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Stack Frame")
        self.SetStringItem(idx, 1, "%d" % func.frame_size)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Size")
        self.SetStringItem(idx, 1, "%d" % func.ext["PAIMEIDiffFunction"].size)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Num Local Vars")
        self.SetStringItem(idx, 1, "%d" % func.num_local_vars)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Num Arguments")
        self.SetStringItem(idx, 1, "%d" % func.num_args)
        idx+=1
        
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Local Var Size")
        self.SetStringItem(idx, 1, "%d" % func.local_var_size)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Arg Size")
        self.SetStringItem(idx, 1, "%d" % func.arg_size)
        idx+=1
        
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "SPP")
        self.SetStringItem(idx, 1, "0x%08x" % func.ext["PAIMEIDiffFunction"].spp)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Smart MD5")
        self.SetStringItem(idx, 1, "%s" % func.ext["PAIMEIDiffFunction"].smart_md5)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "CRC")
        self.SetStringItem(idx, 1, "0x%08x" % func.ext["PAIMEIDiffFunction"].crc)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "NECI")
        self.SetStringItem(idx, 1, "%d:%d:%d:%d" % func.ext["PAIMEIDiffFunction"].neci)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Recursive Call Count")
        self.SetStringItem(idx, 1, "%d" % len(func.ext["PAIMEIDiffFunction"].recursive))
        idx+=1
        self.InsertStringItem(idx, "")
        str_str = ""
        for s in func.ext["PAIMEIDiffFunction"].refs_strings:
            if str_str == "":
                str_str += str(s)
            else:
                str_str += ":" + str(s)
        self.SetStringItem(idx, 0, "String References")
        self.SetStringItem(idx, 1, "%s" % str_str)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Constants References")
        const_str = ""
        for const_s in func.ext["PAIMEIDiffFunction"].refs_constants:
            if const_str == "":
                const_str += str(const_s)
            else:
                const_str += ":" + str(const_s)
        self.SetStringItem(idx, 1, "%s" % const_str)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "API Calls")
        call_str = ""
        for call in func.ext["PAIMEIDiffFunction"].refs_api:
            (ea,c) = call
            if call_str == "":
                call_str += c
            else:
                call_str += ":" + c
        self.SetStringItem(idx, 1, "%s" % call_str)
        idx+=1
        
        
    ####################################################################################################################
    def load_basic_block_stats(self, bb_start):
        '''
        load the basic block specific statistics
        '''
        self.DeleteAllItems()
        idx = 0
       
        if self.name_ctrl == "A":
            function = self.top.matched_list.matched_functions[ self.top.MatchedAListCtrl.curr ]
            (func,func_b) = function
        elif self.name_ctrl == "B":
            function = self.top.matched_list.matched_functions[ self.top.MatchedBListCtrl.curr ]
            (func_a, func) = function
        else:
            func = self.parent.parent.function_list[ self.parent.parent.curr]

#        print "A %d: func: %s" % (self.top.MatchedAListCtrl.curr , func.name)
#        print "B %d: func: %s" % (self.top.MatchedBListCtrl.curr , func.name)


        bb = None
        start=""

        for bb in func.sorted_nodes():
            start = str(hex(bb.ea_start)) 

            
            if len(start) != 10:
                d = 10 - len(start) 
                start = "0x" + "0" * 2 + start[2:]                
#            print "%s == %s" % (start, bb_start)
            if start == bb_start:
#                print "found"
                break
        if bb == None:
            for bb in func.sorted_nodes():
                start = hex(bb.ea_start)
                end   = hex(bb.ea_end)
                bb_s = hex(bb_start)
                if bb_s >= start and bb_s <= end:
                    break
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Name")
        self.SetStringItem(idx, 1, "%s" % func.name)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "EA Start")
        self.SetStringItem(idx, 1, "0x%08x" % bb.ea_start)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "EA End")
        self.SetStringItem(idx, 1, "0x%08x" % bb.ea_end)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Instruction Count")
        self.SetStringItem(idx, 1, "%d" % bb.num_instructions)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Call Count")
        self.SetStringItem(idx, 1, "%d" % bb.ext["PAIMEIDiffBasicBlock"].num_calls)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Size")
        self.SetStringItem(idx, 1, "%d" % bb.ext["PAIMEIDiffBasicBlock"].size)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "SPP")
        self.SetStringItem(idx, 1, "0x%08x" % bb.ext["PAIMEIDiffBasicBlock"].spp)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Smart MD5")
        self.SetStringItem(idx, 1, "%s" % bb.ext["PAIMEIDiffBasicBlock"].smart_md5)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "CRC")
        self.SetStringItem(idx, 1, "0x%08x" % bb.ext["PAIMEIDiffBasicBlock"].crc)
        idx+=1
        self.InsertStringItem(idx, "")
        str_str = ""
        for s in bb.ext["PAIMEIDiffBasicBlock"].refs_strings:
            if str_str == "":
                str_str += str(s)
            else:
                str_str += ":" + str(s)
        self.SetStringItem(idx, 0, "String References")
        self.SetStringItem(idx, 1, "%s" % str_str)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "Constants References")
        const_str = ""
        for const_s in bb.ext["PAIMEIDiffBasicBlock"].refs_constants:
            if const_str == "":
                const_str += str(const_s)
            else:
                const_str += ":" + str(const_s)
        self.SetStringItem(idx, 1, "%s" % const_str)
        idx+=1
        self.InsertStringItem(idx, "")
        self.SetStringItem(idx, 0, "API Calls")
        call_str = ""
        for call in bb.ext["PAIMEIDiffBasicBlock"].refs_api:
            (ea,s) = call
            if call_str == "":
                call_str += s
            else:
                call_str += ":" + s
        self.SetStringItem(idx, 1, "%s" % call_str)
        idx+=1
