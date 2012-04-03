#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PAIMEIpstalker.py 241 2010-04-05 20:45:22Z rgovostes $
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
import sys

import _PAIMEIpstalker

########################################################################################################################
class PAIMEIpstalker(wx.Panel):
    '''
    The Process Stalker module panel.
    '''

    documented_properties = {
        "pida_modules"          : "Dictionary of loaded PIDA modules.",
        "filter_list"           : "List of (target, tag ID) tuples to filter from stalk.",
        "stalk_tag"             : "ID of tag to use for stalk.",
        "function_count"        : "Total number of loaded functions.",
        "basic_block_count"     : "Total number of loaded basic blocks.",
        "hit_function_count"    : "Total number of hit functions.",
        "hit_basic_block_count" : "Total number of hit basic blocks.",
        "print_bps"             : "Boolean flag controlling whether or not to log individual breakpoints hits. This is an advanced option for which no GUI control exists. It is useful for removing the GUI latency in situations where stalking is producing a large volume of breakpoint hits.",
        "watch"                 : "Instead of attaching to or loading a target process, this option allows you to specify a process name to continuously watch for and attach to as soon as it is spawned. The process name is case insensitive, but you *must* specify the full name and extension. Example: winmine.exe",
    }

    list_book             = None        # handle to list book.
    main_frame            = None        # handle to top most frame.
    pida_modules          = {}          # dictionary of loaded PIDA modules.
    filter_list           = []          # list of (target, tag ID) tuples to filter from stalk.
    stalk_tag             = None        # ID of tag to use for stalk.
    function_count        = 0           # total number of loaded functions.
    basic_block_count     = 0           # total number of loaded basic blocks.
    hit_function_count    = 0           # total number of hit functions.
    hit_basic_block_count = 0           # total number of hit basic blocks.
    print_bps             = True        # flag controlling whether or not to log individual breakpoints hits.
    watch                 = None

    def __init__ (self, *args, **kwds):
        # begin wxGlade: PAIMEIpstalker.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)

        self.log_splitter                 = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER)
        self.log_window                   = wx.Panel(self.log_splitter, -1)
        self.top_window                   = wx.Panel(self.log_splitter, -1)
        self.hits_column                  = wx.SplitterWindow(self.top_window, -1, style=wx.SP_3D|wx.SP_BORDER)
        self.hit_dereference              = wx.Panel(self.hits_column, -1)
        self.hit_list                     = wx.Panel(self.hits_column, -1)
        self.hit_list_container_staticbox = wx.StaticBox(self.hit_list, -1, "Data Exploration")
        self.log_container_staticbox      = wx.StaticBox(self.hit_dereference, -1, "Dereferenced Data")
        self.pydbg_column_staticbox       = wx.StaticBox(self.top_window, -1, "Data Capture")
        self.targets_column_staticbox     = wx.StaticBox(self.top_window, -1, "Data Sources")
        self.retrieve_targets             = wx.Button(self.top_window, -1, "Refresh Target List")
        self.targets                      = _PAIMEIpstalker.TargetsTreeCtrl.TargetsTreeCtrl(self.top_window, -1, top=self, style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER)
        self.pida_modules_static          = wx.StaticText(self.top_window, -1, "PIDA Modules")
        self.pida_modules_list            = _PAIMEIpstalker.PIDAModulesListCtrl.PIDAModulesListCtrl(self.top_window, -1, top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER)
        self.add_module                   = wx.Button(self.top_window, -1, "Add Module(s)")
        self.hits                         = _PAIMEIpstalker.HitsListCtrl.HitsListCtrl(self.hit_list, -1, top=self, style=wx.LC_REPORT|wx.LC_HRULES|wx.SUNKEN_BORDER)
        self.coverage_functions_static    = wx.StaticText(self.hit_list, -1, "Functions:")
        self.coverage_functions           = wx.Gauge(self.hit_list, -1, 100, style=wx.GA_HORIZONTAL|wx.GA_SMOOTH)
        self.basic_blocks_coverage_static = wx.StaticText(self.hit_list, -1, "Basic Blocks:")
        self.coverage_basic_blocks        = wx.Gauge(self.hit_list, -1, 100, style=wx.GA_HORIZONTAL|wx.GA_SMOOTH)
        self.hit_details                  = wx.TextCtrl(self.hit_dereference, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.HSCROLL)
        self.retrieve_list                = wx.Button(self.top_window, -1, "Refresh Process List")
        self.process_list                 = _PAIMEIpstalker.ProcessListCtrl.ProcessListCtrl(self.top_window, -1, top=self, style=wx.LC_REPORT|wx.SUNKEN_BORDER)
        self.load_target                  = filebrowse.FileBrowseButton(self.top_window, -1, labelText="Load: ", fileMask="*.exe", fileMode=wx.OPEN, toolTip="Specify the target executable to load")
        self.coverage_depth               = wx.RadioBox(self.top_window, -1, "Coverage Depth", choices=["Functions", "Basic Blocks"], majorDimension=0, style=wx.RA_SPECIFY_ROWS)
        self.restore_breakpoints          = wx.CheckBox(self.top_window, -1, "Restore BPs")
        self.heavy                        = wx.CheckBox(self.top_window, -1, "Heavy")
        self.ignore_first_chance          = wx.CheckBox(self.top_window, -1, "Unhandled Only")
        self.attach_detach                = wx.Button(self.top_window, -1, "Start Stalking")
        self.log                          = wx.TextCtrl(self.log_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        self.list_book  = kwds["parent"]             # handle to list book.
        self.main_frame = self.list_book.top         # handle to top most frame.

        # default status message.
        self.status_msg = "Process Stalker"

        # log window bindings.
        self.Bind(wx.EVT_TEXT_MAXLEN, self.OnMaxLogLengthReached, self.log)

        # targets / tags tree ctrl.
        self.Bind(wx.EVT_BUTTON,                        self.targets.on_retrieve_targets, self.retrieve_targets)
        self.targets.Bind(wx.EVT_TREE_ITEM_ACTIVATED,   self.targets.on_target_activated)
        self.targets.Bind(wx.EVT_TREE_SEL_CHANGED,      self.targets.on_target_sel_changed)
        self.targets.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.targets.on_target_right_click)
        self.targets.Bind(wx.EVT_RIGHT_UP,              self.targets.on_target_right_click)
        self.targets.Bind(wx.EVT_RIGHT_DOWN,            self.targets.on_target_right_down)

        # pida modules list ctrl.
        self.Bind(wx.EVT_BUTTON,                                self.pida_modules_list.on_add_module, self.add_module)
        self.pida_modules_list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.pida_modules_list.on_right_click)
        self.pida_modules_list.Bind(wx.EVT_RIGHT_UP,            self.pida_modules_list.on_right_click)
        self.pida_modules_list.Bind(wx.EVT_RIGHT_DOWN,          self.pida_modules_list.on_right_down)

        # hit list ctrl.
        self.hits.Bind(wx.EVT_LIST_ITEM_SELECTED, self.hits.on_select)

        # process list ctrl.
        self.Bind(wx.EVT_BUTTON, self.process_list.on_retrieve_list,  self.retrieve_list)
        self.Bind(wx.EVT_BUTTON, self.process_list.on_attach_detach,  self.attach_detach)
        self.process_list.Bind(wx.EVT_LIST_ITEM_SELECTED,             self.process_list.on_select)

        # unselect targets
        self.targets.UnselectAll()

        self.msg("PaiMei Process Stalker")
        self.msg("Module by Pedram Amini\n")


    ####################################################################################################################
    def __set_properties (self):
        # set the max length to whatever the widget supports (typically 32k).
        self.log.SetMaxLength(0)

        # begin wxGlade: PAIMEIpstalker.__set_properties
        self.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.retrieve_targets.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.targets.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.pida_modules_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.pida_modules_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.add_module.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.hits.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.coverage_functions_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.coverage_functions.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.basic_blocks_coverage_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.coverage_basic_blocks.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.hit_details.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "Courier"))
        self.hits_column.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.retrieve_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.process_list.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.load_target.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.coverage_depth.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.coverage_depth.SetSelection(0)
        self.restore_breakpoints.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.heavy.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.heavy.SetValue(1)
        self.ignore_first_chance.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.ignore_first_chance.SetValue(1)
        self.attach_detach.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.top_window.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.log.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.log_splitter.SetMinimumPaneSize(25)
        # end wxGlade


    ####################################################################################################################
    def __do_layout (self):
        # begin wxGlade: PAIMEIpstalker.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        log_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        columns = wx.BoxSizer(wx.HORIZONTAL)
        pydbg_column = wx.StaticBoxSizer(self.pydbg_column_staticbox, wx.VERTICAL)
        stalk_options = wx.BoxSizer(wx.HORIZONTAL)
        log_container = wx.StaticBoxSizer(self.log_container_staticbox, wx.HORIZONTAL)
        hit_list_container = wx.StaticBoxSizer(self.hit_list_container_staticbox, wx.VERTICAL)
        percent_coverage = wx.BoxSizer(wx.HORIZONTAL)
        basic_blocks_block = wx.BoxSizer(wx.VERTICAL)
        functions_block = wx.BoxSizer(wx.VERTICAL)
        targets_column = wx.StaticBoxSizer(self.targets_column_staticbox, wx.VERTICAL)
        targets_column.Add(self.retrieve_targets, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        targets_column.Add(self.targets, 4, wx.EXPAND, 0)
        targets_column.Add(self.pida_modules_static, 0, wx.ADJUST_MINSIZE, 0)
        targets_column.Add(self.pida_modules_list, 2, wx.EXPAND, 0)
        targets_column.Add(self.add_module, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        columns.Add(targets_column, 1, wx.EXPAND, 0)
        hit_list_container.Add(self.hits, 3, wx.EXPAND, 0)
        functions_block.Add(self.coverage_functions_static, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        functions_block.Add(self.coverage_functions, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        percent_coverage.Add(functions_block, 1, wx.EXPAND, 0)
        percent_coverage.Add((50, 20), 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        basic_blocks_block.Add(self.basic_blocks_coverage_static, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        basic_blocks_block.Add(self.coverage_basic_blocks, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        percent_coverage.Add(basic_blocks_block, 1, wx.EXPAND, 0)
        hit_list_container.Add(percent_coverage, 0, wx.EXPAND, 0)
        self.hit_list.SetAutoLayout(True)
        self.hit_list.SetSizer(hit_list_container)
        hit_list_container.Fit(self.hit_list)
        hit_list_container.SetSizeHints(self.hit_list)
        log_container.Add(self.hit_details, 2, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.hit_dereference.SetAutoLayout(True)
        self.hit_dereference.SetSizer(log_container)
        log_container.Fit(self.hit_dereference)
        log_container.SetSizeHints(self.hit_dereference)
        self.hits_column.SplitHorizontally(self.hit_list, self.hit_dereference)
        columns.Add(self.hits_column, 2, wx.EXPAND, 0)
        pydbg_column.Add(self.retrieve_list, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        pydbg_column.Add(self.process_list, 5, wx.EXPAND, 0)
        pydbg_column.Add(self.load_target, 0, wx.EXPAND, 0)
        pydbg_column.Add(self.coverage_depth, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        stalk_options.Add(self.restore_breakpoints, wx.EXPAND, wx.ADJUST_MINSIZE, 0)
        stalk_options.Add(self.heavy, wx.EXPAND, wx.ADJUST_MINSIZE, 0)
        stalk_options.Add(self.ignore_first_chance, wx.EXPAND, wx.ADJUST_MINSIZE, 0)
        pydbg_column.Add((5, 10), 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        pydbg_column.Add(stalk_options, 0, wx.EXPAND, 0)
        pydbg_column.Add((5, 10), 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        pydbg_column.Add(self.attach_detach, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        columns.Add(pydbg_column, 1, wx.EXPAND, 0)
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
    def _get_status (self):
        '''
        Return the text to display in the status bar on page change.
        '''

        return self.status_msg


    ####################################################################################################################
    def _set_status (self, status_msg):
        '''
        Set the text to display in the status bar.
        '''

        self.status_msg = status_msg
        self.main_frame.status_bar.SetStatusText(self.status_msg, 1)


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
    def update_gauges (self):
        '''
        '''

        self.coverage_functions_static.SetLabel("Functions: %d / %d" % (self.hit_function_count, self.function_count))
        self.basic_blocks_coverage_static.SetLabel("Basic Blocks: %d / %d" % (self.hit_basic_block_count, self.basic_block_count))

        msg = ""

        if self.function_count:
            percent = int((float(self.hit_function_count) / float(self.function_count)) * 100)
            msg += "Function coverage at %d%%. " % percent
        else:
            percent = 0

        self.coverage_functions.SetValue(percent)

        if self.basic_block_count:
            percent = int((float(self.hit_basic_block_count) / float(self.basic_block_count)) * 100)
            msg += "Basic block coverage at %d%%." % percent
        else:
            percent = 0

        if msg:
            self.msg(msg)

        self.coverage_basic_blocks.SetValue(percent)
