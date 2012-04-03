#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PAIMEIexplorer.py 194 2007-04-05 15:31:53Z cameron $
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
import wx.html as html

import sys

import _PAIMEIexplorer

#######################################################################################################################
class PAIMEIexplorer (wx.Panel):
    '''
    The PIDA module explorer panel.
    '''

    documented_properties = {
        "pida_modules"           : "Dictionary of loaded PIDA modules.",
        "pida_copy(module_name)" : "Copy the specified module from pstalker to the explorer pane.",
    }

    list_book    = None      # handle to list book.
    main_frame   = None      # handle to top most frame.
    pida_modules = {}        # dictionary of loaded PIDA modules.

    def __init__(self, *args, **kwds):
        # begin wxGlade: PAIMEIexplorer.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)

        self.log_splitter                = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER)
        self.log_window                  = wx.Panel(self.log_splitter, -1)
        self.top_window                  = wx.Panel(self.log_splitter, -1)
        self.disassmbly_column_staticbox = wx.StaticBox(self.top_window, -1, "Disassembly")
        self.special_column_staticbox    = wx.StaticBox(self.top_window, -1, "Special")
        self.browser_column_staticbox    = wx.StaticBox(self.top_window, -1, "Browser")
        self.pida_modules_static         = wx.StaticText(self.top_window, -1, "PIDA Modules")
        self.pida_modules_list           = _PAIMEIexplorer.PIDAModulesListCtrl.PIDAModulesListCtrl(self.top_window, -1, top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER)
        self.add_module                  = wx.Button(self.top_window, -1, "Add Module(s)")
        self.explorer                    = _PAIMEIexplorer.ExplorerTreeCtrl.ExplorerTreeCtrl(self.top_window, -1, top=self, style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER)
        self.disassembly                 = _PAIMEIexplorer.HtmlWindow.HtmlWindow(self.top_window, -1, top=self, style=wx.NO_FULL_REPAINT_ON_RESIZE)
        self.special                     = wx.TextCtrl(self.top_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY)
        self.log                         = wx.TextCtrl(self.log_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        # set the default sash position to be 100 pixels from the bottom (small log window).
        self.log_splitter.SetSashPosition(-100)

        self.list_book    = kwds["parent"]             # handle to list book.
        self.main_frame   = self.list_book.top         # handle to top most frame.

        # log window bindings.
        self.Bind(wx.EVT_TEXT_MAXLEN, self.OnMaxLogLengthReached, self.log)

        # explorer tree ctrl.
        self.explorer.Bind(wx.EVT_TREE_ITEM_ACTIVATED,   self.explorer.on_item_activated)
        self.explorer.Bind(wx.EVT_TREE_SEL_CHANGED,      self.explorer.on_item_sel_changed)
        self.explorer.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.explorer.on_item_right_click)
        self.explorer.Bind(wx.EVT_RIGHT_UP,              self.explorer.on_item_right_click)
        self.explorer.Bind(wx.EVT_RIGHT_DOWN,            self.explorer.on_item_right_down)

        # pida modules list ctrl.
        self.Bind(wx.EVT_BUTTON,                                self.pida_modules_list.on_add_module, self.add_module)
        self.pida_modules_list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.pida_modules_list.on_right_click)
        self.pida_modules_list.Bind(wx.EVT_RIGHT_UP,            self.pida_modules_list.on_right_click)
        self.pida_modules_list.Bind(wx.EVT_RIGHT_DOWN,          self.pida_modules_list.on_right_down)
        self.pida_modules_list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.pida_modules_list.on_activated)

        self.msg("PaiMei Explorer")
        self.msg("Module by Pedram Amini\n")


    ####################################################################################################################
    def __set_properties (self):
        # set the max length to whatever the widget supports (typically 32k).
        self.log.SetMaxLength(0)

        # begin wxGlade: PAIMEIexplorer.__set_properties
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.pida_modules_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.pida_modules_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.add_module.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.explorer.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.special.SetFont(wx.Font(10, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Courier"))
        self.log.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.log_splitter.SetMinimumPaneSize(25)
        # end wxGlade


    ####################################################################################################################
    def __do_layout (self):
        # begin wxGlade: PAIMEIexplorer.__do_layout
        overall = wx.BoxSizer(wx.HORIZONTAL)
        log_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        columns = wx.BoxSizer(wx.HORIZONTAL)
        special_column = wx.StaticBoxSizer(self.special_column_staticbox, wx.VERTICAL)
        disassmbly_column = wx.StaticBoxSizer(self.disassmbly_column_staticbox, wx.VERTICAL)
        browser_column = wx.StaticBoxSizer(self.browser_column_staticbox, wx.VERTICAL)
        browser_column.Add(self.pida_modules_static, 0, wx.ADJUST_MINSIZE, 0)
        browser_column.Add(self.pida_modules_list, 1, wx.EXPAND, 0)
        browser_column.Add(self.add_module, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        browser_column.Add(self.explorer, 5, wx.EXPAND, 0)
        columns.Add(browser_column, 1, wx.EXPAND, 0)
        disassmbly_column.Add(self.disassembly, 1, wx.GROW, 0)
        columns.Add(disassmbly_column, 2, wx.EXPAND, 0)
        special_column.Add(self.special, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        columns.Add(special_column, 1, wx.EXPAND, 0)
        self.top_window.SetAutoLayout(True)
        self.top_window.SetSizer(columns)
        columns.Fit(self.top_window)
        columns.SetSizeHints(self.top_window)
        log_window_sizer.Add(self.log, 1, wx.EXPAND, 0)
        self.log_window.SetAutoLayout(True)
        self.log_window.SetSizer(log_window_sizer)
        log_window_sizer.Fit(self.log_window)
        log_window_sizer.SetSizeHints(self.log_window)
        self.log_splitter.SplitHorizontally(self.top_window, self.log_window)
        overall.Add(self.log_splitter, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        # end wxGlade


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
    def pida_copy (self, module_name):
        '''
        Load the specified module name from the pstalker module directly into the explorer tree control.

        @type  module_name: String
        @param module_name: Name of module to copy and load from pstalker module.
        '''

        other = self.main_frame.modules["pstalker"].pida_modules

        if not other.has_key(module_name):
            self.err("Specified module name %s, not found." % module_name)
            return

        self.pida_modules[module_name] = other[module_name]

        # determine the function and basic block counts for this module.
        function_count    = len(self.pida_modules[module_name].nodes)
        basic_block_count = 0

        for function in self.pida_modules[module_name].nodes.values():
            basic_block_count += len(function.nodes)

        idx = len(self.pida_modules) - 1
        self.pida_modules_list.InsertStringItem(idx, "")
        self.pida_modules_list.SetStringItem(idx, 0, "%d" % function_count)
        self.pida_modules_list.SetStringItem(idx, 1, "%d" % basic_block_count)
        self.pida_modules_list.SetStringItem(idx, 2, module_name)