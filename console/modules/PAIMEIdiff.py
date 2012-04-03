#
# PaiMei
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: PAIMEIdiff.py 194 2007-04-05 15:31:53Z cameron $
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
import _PAIMEIdiff
import sys
import os
sys.path.append("modules/_PAIMEIdiff/DiffModules")

# begin wxGlade: dependencies
# end wxGlade

class PAIMEIdiff(wx.Panel):
    '''
    The bin diff module panel.
    '''
    
    documented_variables = {
    }
    pida_modules = {}
    def __init__(self, *args, **kwds):
        # begin wxGlade: PAIMEIdiff.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)
        self.log_splitter               = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER)
        self.log_window                 = wx.Panel(self.log_splitter, -1)
        self.top_window                 = wx.Panel(self.log_splitter, -1)
        self.matchbook                  = wx.Notebook(self.top_window, -1, style=0)
        self.matchbook_unmatched_a      = wx.Panel(self.matchbook, -1)
        self.matchbook_matched          = wx.Panel(self.matchbook, -1)
        self.module_b_sizer_staticbox   = wx.StaticBox(self, -1, "Module B")
        self.module_a_sizer_staticbox   = wx.StaticBox(self, -1, "Module A")
        
               
        self.module_a                   = _PAIMEIdiff.ExplorerTreeCtrl.ExplorerTreeCtrl(self, -1, top=self, style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER, name="A")
        self.module_a_load              = wx.Button(self, -1, "Load")
        self.module_b                   = _PAIMEIdiff.ExplorerTreeCtrl.ExplorerTreeCtrl(self, -1, top=self, style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER, name="B")
        self.module_b_load              = wx.Button(self, -1, "Load")
                                        
        self.MatchedAListCtrl           = _PAIMEIdiff.MatchedListCtrl.MatchedListCtrl(self.matchbook_matched, -1, top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER | wx.LC_SINGLE_SEL )
        self.MatchedBListCtrl           = _PAIMEIdiff.MatchedListCtrl.MatchedListCtrl(self.matchbook_matched, -1, top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER | wx.LC_SINGLE_SEL )
        self.UnMatchedAListCtrl         = _PAIMEIdiff.UnmatchedListCtrl.UnmatchedListCtrl(self.matchbook_unmatched_a, -1,top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER | wx.LC_SINGLE_SEL )
        self.UnMatchedBListCtrl         = _PAIMEIdiff.UnmatchedListCtrl.UnmatchedListCtrl(self.matchbook_unmatched_a, -1,top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER | wx.LC_SINGLE_SEL )
        
        self.configure                  = wx.Button(self.top_window, -1, "Configure")
        self.execute                    = wx.Button(self.top_window, -1, "Execute")
        self.exp                        = wx.Button(self.top_window, -1, "Export")
        self.info                       = wx.TextCtrl(self.top_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)
        self.log                        = wx.TextCtrl(self.log_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)
        
        self.__set_properties()
        self.__do_layout()
        # end wxGlade
        
        #flag to tell us to ignore insignificant variables
        self.ignore_insignificant = 0
        #flag tells us to loop until we don't have a change
        self.loop_until_change  = 0
        
        #our default values for the insiginificant functions
        self.insignificant_function = (1,1,1,1)
        #our default value for the insignificant basic block
        self.insignificant_bb = 2
        #function pointer tables its where functions get registered
        self.match_function_table       = {}
        self.match_basic_block_table    = {}
        self.diff_function_table        = {}
        self.diff_basic_block_table     = {}
        self.used_match_function_table       = {}
        self.used_match_basic_block_table    = {}
        self.used_diff_function_table        = {}
        self.used_diff_basic_block_table     = {}
        #table contains references to all the modules related to diffing/matching
        self.module_table               = {}
        #our list that contains the matched functions
        self.matched_list       = _PAIMEIdiff.MatchedList.MatchedList(parent=self) 
        self.unmatched_list     = _PAIMEIdiff.UnmatchedList.UnmatchedList()
        
        self.insig_a_list       = []
        self.insig_b_list       = []
        self.module_a_name      = ""
        self.module_b_name      = ""
        
        self.crc_table = {}
     
        self.list_book  = kwds["parent"]             # handle to list book.
        self.main_frame = self.list_book.top         # handle to top most frame.
        
        self.crc_build_table()
        
        
       
                     
        # log window bindings.
        self.Bind(wx.EVT_TEXT_MAXLEN,   self.OnMaxLogLengthReached, self.log)
        self.Bind(wx.EVT_BUTTON,        self.module_a.load_module,  self.module_a_load)
        self.Bind(wx.EVT_BUTTON,        self.module_b.load_module,  self.module_b_load)
        self.Bind(wx.EVT_BUTTON,        self.on_configure,          self.configure)
        self.Bind(wx.EVT_BUTTON,        self.on_execute,            self.execute)
        self.Bind(wx.EVT_BUTTON,        self.on_export,             self.exp)
        
        
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnListItemSelectedA,      self.MatchedAListCtrl)
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnListItemSelectedB,      self.MatchedBListCtrl)
        #self.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.MatchedAListCtrl.OnListItemRightClick,  self.MatchedAListCtrl)
        self.MatchedAListCtrl.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.MatchedAListCtrl.OnRightClick)
        self.MatchedBListCtrl.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.MatchedBListCtrl.OnRightClick)
         
        self.UnMatchedAListCtrl.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.UnMatchedAListCtrl.OnRightClick)
        self.UnMatchedBListCtrl.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.UnMatchedBListCtrl.OnRightClick)

        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnListItemSelectedUnmatchA,      self.UnMatchedAListCtrl)
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnListItemSelectedUnmatchB,      self.UnMatchedBListCtrl)
        
        
        self.msg("PaiMei Binary Diffing Engine")
        self.msg("Module by Peter Silberman\n")
        
        #dynamically load the matching/diffing modules
        for mod in os.listdir("modules/_PAIMEIdiff/DiffModules"):
            if mod.endswith(".py") and mod != "defines.py":
                try:
                    module       = mod.replace(".py", "")
                    exec("from %s import *" % module)

                    exec("%s(parent=self)" % module)

                    
                except:
                    import traceback
                    traceback.print_exc(file=sys.stdout)

                    
   
    ####################################################################################################################
    def __set_properties(self):
        # begin wxGlade: PAIMEIdiff.__set_properties
        self.info.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.log.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        # end wxGlade

	####################################################################################################################
    def __do_layout(self):
        # begin wxGlade: PAIMEIdiff.__do_layout
        overall = wx.BoxSizer(wx.HORIZONTAL)
        log_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        top_window_sizer = wx.BoxSizer(wx.VERTICAL)
        middle_sizer = wx.BoxSizer(wx.HORIZONTAL)
        actions_sizer = wx.GridSizer(2, 2, 0, 0)
        sizer_9 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_11 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_3 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_12 = wx.BoxSizer(wx.HORIZONTAL)
        modules_sizer = wx.BoxSizer(wx.VERTICAL)
        module_b_sizer = wx.StaticBoxSizer(self.module_b_sizer_staticbox, wx.VERTICAL)
        module_a_sizer = wx.StaticBoxSizer(self.module_a_sizer_staticbox, wx.VERTICAL)
        module_a_sizer.Add(self.module_a, 2, wx.EXPAND, 0)
        module_a_sizer.Add(self.module_a_load, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        modules_sizer.Add(module_a_sizer, 1, wx.EXPAND, 0)
        module_b_sizer.Add(self.module_b, 2, wx.EXPAND, 0)
        module_b_sizer.Add(self.module_b_load, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        modules_sizer.Add(module_b_sizer, 1, wx.EXPAND, 0)
        overall.Add(modules_sizer, 1, wx.EXPAND, 0)
        sizer_12.Add(self.MatchedAListCtrl, 1, wx.EXPAND, 0)
        sizer_12.Add(self.MatchedBListCtrl, 1, wx.EXPAND, 0)
        sizer_3.Add(sizer_12, 1, wx.EXPAND, 0)
        self.matchbook_matched.SetAutoLayout(True)
        self.matchbook_matched.SetSizer(sizer_3)
        sizer_3.Fit(self.matchbook_matched)
        sizer_3.SetSizeHints(self.matchbook_matched)
        sizer_11.Add(self.UnMatchedAListCtrl, 1, wx.EXPAND, 0)
        sizer_11.Add(self.UnMatchedBListCtrl, 1, wx.EXPAND, 0)
        sizer_9.Add(sizer_11, 1, wx.EXPAND, 0)
        self.matchbook_unmatched_a.SetAutoLayout(True)
        self.matchbook_unmatched_a.SetSizer(sizer_9)
        sizer_9.Fit(self.matchbook_unmatched_a)
        sizer_9.SetSizeHints(self.matchbook_unmatched_a)
        self.matchbook.AddPage(self.matchbook_matched, "Matched")
        self.matchbook.AddPage(self.matchbook_unmatched_a, "Unmatched Functions")
        top_window_sizer.Add(self.matchbook, 4, wx.EXPAND, 0)
        actions_sizer.Add(self.configure, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        actions_sizer.Add(self.execute, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        actions_sizer.Add(self.exp, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        middle_sizer.Add(actions_sizer, 1, wx.EXPAND, 0)
        middle_sizer.Add(self.info, 1, wx.EXPAND, 0)
        top_window_sizer.Add(middle_sizer, 1, wx.EXPAND, 0)
        self.top_window.SetAutoLayout(True)
        self.top_window.SetSizer(top_window_sizer)
        top_window_sizer.Fit(self.top_window)
        top_window_sizer.SetSizeHints(self.top_window)
        log_window_sizer.Add(self.log, 1, wx.EXPAND, 0)
        self.log_window.SetAutoLayout(True)
        self.log_window.SetSizer(log_window_sizer)
        log_window_sizer.Fit(self.log_window)
        log_window_sizer.SetSizeHints(self.log_window)
        self.log_splitter.SplitHorizontally(self.top_window, self.log_window)
        overall.Add(self.log_splitter, 3, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        # end wxGlade

# end of class PAIMEIdiff



    ####################################################################################################################
    def _get_status (self):
        '''
        Return the text to display in the status bar on page change.
        '''

        return "Binary Diffing Engine"

        
    ####################################################################################################################
    def _set_status (self, msg):
        '''
        Set the text to display in the status bar.
        '''

        self.main_frame.status_bar.SetStatusText(msg, 1)


    ####################################################################################################################
    def OnMaxLogLengthReached (self, event):
        '''
        Clear the log window when the max length is reach.
        
        @todo: Make this smarter by maybe only clearing half the lines.
        '''
        
        self.log.SetValue("")


    ####################################################################################################################
    def err (self, message):
        '''
        Write an error message to log window.
        '''

        self.log.AppendText("[!] %s\n" % message)


    ####################################################################################################################
    def msg (self, message):
        '''
        Write a log message to log window.
        '''

        self.log.AppendText("[*] %s\n" % message)
    ####################################################################################################################
    def on_configure(self, event):
        '''
        Display the configure dialog box
        '''
        dlg = _PAIMEIdiff.DiffConfigureDlg.DiffConfigureDlg(parent=self)
        dlg.ShowModal()
        
    ####################################################################################################################
    def on_export(self, event):
        '''
        Export the diffing results to an html web page
        '''
        dlg = wx.DirDialog(self, "Choose a directory:",
                          style=wx.DD_DEFAULT_STYLE|wx.DD_NEW_DIR_BUTTON)
        if dlg.ShowModal() != wx.ID_OK:
            self.err("You need to select a directory to output the report to")
        else:
            path = dlg.GetPath() + "\\"
            report = _PAIMEIdiff.PAIMEIDiffReport.PAIMEIDiffReport(self,path)
            report.generate_report()
        
    ####################################################################################################################
    def on_execute(self, event):
        '''
        Execute the matching/diffing algorithms.
        '''
        self.msg("Using an Insignificant function definition of %d:%d:%d:%d" % self.insignificant_function)
        self.msg("Using an Insignificant BB definition of %d" % self.insignificant_bb)
        mod_a = self.pida_modules[self.module_a_name]
        mod_b = self.pida_modules[self.module_b_name]
        
        mm = _PAIMEIdiff.ModuleMatcher.ModuleMatcher(self,mod_a,mod_b)
        mm.match_modules()
        md = _PAIMEIdiff.ModuleDiffer.ModuleDiffer(self)
        md.diff_modules()
        self.msg("Number of different functions: %d" % self.matched_list.num_different_functions)
        self.DisplayMatched()
        self.DisplayUnmatched()
        
        
    ####################################################################################################################
    def OnListItemSelectedA(self, evt):
        curr = evt.m_itemIndex
        self.MatchedBListCtrl.curr = curr
        self.MatchedAListCtrl.curr = curr
        item = self.MatchedBListCtrl.GetItem(curr)
        item.m_stateMask = wx.LIST_STATE_SELECTED  
        item.m_state     = wx.LIST_STATE_SELECTED  
        self.MatchedBListCtrl.SetItem(item)
        self.MatchedBListCtrl.EnsureVisible(curr)
        
    ####################################################################################################################        
    def OnListItemSelectedB(self, evt):
        curr = evt.m_itemIndex
        self.MatchedBListCtrl.curr = curr
        self.MatchedAListCtrl.curr = curr
        item = self.MatchedAListCtrl.GetItem(curr)
        item.m_stateMask = wx.LIST_STATE_SELECTED  
        item.m_state     = wx.LIST_STATE_SELECTED  
        self.MatchedAListCtrl.SetItem(item)
        self.MatchedAListCtrl.EnsureVisible(curr)

    ####################################################################################################################
    def OnListItemSelectedUnmatchA(self,evt):
        self.UnMatchedAListCtrl.curr = evt.m_itemIndex
        
    ####################################################################################################################
    def OnListItemSelectedUnmatchB(self,evt):
        self.UnMatchedBListCtrl.curr = evt.m_itemIndex
        
    ####################################################################################################################
    def manual_match_function(self):
        '''
        Allows the user to manually match functions
        '''
        if self.UnMatchedAListCtrl.curr == -1 and self.UnMatchedAListCtrl.curr <= self.UnMatchedAListCtrl.GetItemCount():
            self.err("Please select a function in unmatched module a to match with unmatched module b")
            return
        if self.UnMatchedBListCtrl.curr == -1 and self.UnMatchedBListCtrl.curr <= self.UnMatchedBListCtrl.GetItemCount():
            self.err("Please select a function in unmatched module b to match with unmatched module a")
            return
            
        func_a = self.UnMatchedAListCtrl.function_list[ self.UnMatchedAListCtrl.curr ]
        func_b = self.UnMatchedBListCtrl.function_list[ self.UnMatchedBListCtrl.curr ]
        
        del self.UnMatchedAListCtrl.function_list[ self.UnMatchedAListCtrl.curr ]
        del self.UnMatchedBListCtrl.function_list[ self.UnMatchedBListCtrl.curr ]
        
        self.UnMatchedAListCtrl.DeleteItem( self.UnMatchedAListCtrl.curr )
        self.UnMatchedBListCtrl.DeleteItem( self.UnMatchedBListCtrl.curr )
        
        
        self.matched_list.add_matched_function(func_a, func_b, "Manual")
        
        
        self.MatchedAListCtrl.add_function(func_a,-1)
        self.MatchedBListCtrl.add_function(func_b,-1)


    ####################################################################################################################
    def unmatch_function(self):
        '''
        Allows the user to un matched previously matched functions
        '''
        if self.MatchedAListCtrl.curr == -1 and self.MatchedAListCtrl.curr <= self.MatchedAListCtrl.GetItemCount():
            self.err("Please select a function in module a to unmatch")
            return
        if self.MatchedBListCtrl.curr == -1 and self.MatchedBListCtrl.curr <= self.MatchedBListCtrl.GetItemCount():
            self.err("Please select a function in module b to unmatch")
            return

        (func_a, func_b) = self.matched_list.unmatch_function( self.MatchedAListCtrl.curr )
                
        self.MatchedAListCtrl.DeleteItem( self.MatchedAListCtrl.curr )
        self.MatchedBListCtrl.DeleteItem( self.MatchedBListCtrl.curr )

        self.UnMatchedAListCtrl.add_function(func_a,-1)
        self.UnMatchedBListCtrl.add_function(func_b,-1)

        

    
    def crc_build_table(self):
        '''
        Build the CRC table to be used in our CRC checksumming

        '''
        crc = 0
        polynomial = 0xEDB88320L
        i = 0
        j = 0
        for i in range(i, 256,1):
            crc = i
            j = 8
            while j > 0:
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
                j-=1
            self.crc_table[ i ] = crc

    def register_match_function(self, function, ref):
        '''
        Register a function to be used in the function matching phase.
        '''
        self.match_function_table[ ref.module_name ] = function
    
    def register_match_basic_block(self, function, ref):
        '''
        Register a function to be used in the basic block matching phase.
        '''
        self.match_basic_block_table[ ref.module_name ] = function
        
    def register_diff_function(self, function, ref):
        '''
        Register a function to be used in the function diffing phase.
        '''
        self.diff_function_table[ ref.module_name ] = function
        
    def register_diff_basic_block(self, function, ref):
        '''
        Register a function to be used in the basic block diffing phase.
        '''
        self.diff_basic_block_table[ ref.module_name ] = function
        
    def register_module(self, ref):
        '''
        Register a module thats being used in the fuction/basic block diffing/matching.
        '''
        self.module_table[ ref.module_name ] = ref

    def DisplayMatched(self):
        '''
        Display the matched functions.
        '''
        self.MatchedAListCtrl.DeleteAllItems()
        self.MatchedBListCtrl.DeleteAllItems()
        i = 0
        while i < self.matched_list.num_matched_functions:
            (func_a, func_b) = self.matched_list.matched_functions[i]
            #print "%s %s %d" % (func_a.name, func_b.name, i)
            self.MatchedAListCtrl.add_function(func_a,i)
            self.MatchedBListCtrl.add_function(func_b,i)
            i+=1
            
    def DisplayUnmatched(self):
        '''
        Display the un matched functions.
        '''
        self.UnMatchedAListCtrl.DeleteAllItems()
        self.UnMatchedBListCtrl.DeleteAllItems()
        i = 0
        while i < len(self.unmatched_list.unmatched_module_a):
            self.UnMatchedAListCtrl.add_function(self.unmatched_list.unmatched_module_a[i],i)
            i+=1
        i = 0
        while i < len(self.unmatched_list.unmatched_module_b):
            self.UnMatchedBListCtrl.add_function(self.unmatched_list.unmatched_module_b[i],i)
            i+=1    
            