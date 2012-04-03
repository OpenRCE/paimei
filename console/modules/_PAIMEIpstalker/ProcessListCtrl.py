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
        self.restore_breakpoints = False
        self.selected_pid        = 0
        self.selected_proc       = None
        self.process_stalker     = None

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
    def on_attach_detach (self, event):
        '''
        This is the meat and potatoes. Grab the coverage depth, attach to the selected process, load the appropriate
        modules ... etc etc.
        '''

        ###
        ### detaching ...
        ###

        if self.process_stalker:
            self.process_stalker.detach = True
            self.process_stalker        = None

            self.top.attach_detach.SetLabel("Start Stalking")
            return

        ###
        ### attaching / loading ...
        ###

        # sanity checking.
        if not len(self.top.pida_modules):
            self.top.err("You must load at least one PIDA file.")
            return

        if not self.top.stalk_tag:
            self.top.err("You must select a tag for code coverage data storage.")
            return

        # pull the value from the load target control, if anything is specified.
        load_value = self.top.load_target.GetValue().rstrip(" ").lstrip(" ")

        if not self.selected_pid and not load_value and not self.top.watch:
            self.top.err("You must select a target process or executable to stalk.")
            return

        for module in self.top.pida_modules:
            self.top.msg("Stalking module %s" % module)

        # create a new debugger instance for this stalk.
        if hasattr(self.top.main_frame.pydbg, "port"):
            dbg = pydbg_client(self.top.main_frame.pydbg.host, self.top.main_frame.pydbg.port)
        else:
            dbg = pydbg()

        # we are loading a target to stalk. (filled load control takes precedence over selected process)
        if load_value:
            # look for a quotation mark, any quotation mark will do but if there is one present we also need to know
            # the location of the second one, so just start off by looking for that now.
            second_quote = load_value.find('"', 1)

            if second_quote != -1:
                load   = load_value[1:second_quote]
                args   = load_value[second_quote+1:]
                attach = None
            else:
                load   = load_value
                args   = None
                attach = None

            main = load

            if main.rfind("\\"):
                main = main[main.rfind("\\")+1:]

        elif self.top.watch:
            process_found = False

            self.top.msg("Watching for process: %s" % self.top.watch)

            while not process_found:
                for (pid, proc_name) in dbg.enumerate_processes():
                    wx.Yield()
                    if proc_name.lower() == self.top.watch.lower():
                        process_found = True
                        break

            self.top.msg("Found target process at %d (0x04x)" % (pid, pid))

            attach = pid
            main   = proc_name.lower()
            load   = None
            args   = None

        # we are attaching a target to stalk.
        else:
            attach = self.selected_pid
            main   = self.selected_proc.lower()
            load   = None
            args   = None

        self.process_stalker = utils.process_stalker(                       \
            attach              = attach,                                   \
            load                = load,                                     \
            args                = args,                                     \
            filter_list         = self.top.filter_list,                     \
            heavy               = self.top.heavy.GetValue(),                \
            ignore_first_chance = self.top.ignore_first_chance.GetValue(),  \
            log                 = self.top.msg,                             \
            main                = main,                                     \
            mysql               = self.top.main_frame.mysql,                \
            pida_modules        = self.top.pida_modules,                    \
            pydbg               = dbg,                                      \
            print_bps           = self.top.print_bps,                       \
            restore             = self.top.restore_breakpoints.GetValue(),  \
            tag_id              = self.top.stalk_tag["id"],                 \
            target_id           = self.top.stalk_tag["target_id"],          \
            depth               = self.top.coverage_depth.GetSelection()    \
        )

        self.top.attach_detach.SetLabel("Stop Stalking")
        self.process_stalker.stalk()

        # reset state after stalking is finished.
        self.top.attach_detach.SetLabel("Start Stalking")
        self.process_stalker = None


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