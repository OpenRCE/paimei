#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PIDAModulesListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
import os
import sys
import time

from wx.lib.mixins.listctrl import ColumnSorterMixin
from wx.lib.mixins.listctrl import ListCtrlAutoWidthMixin

sys.path.append("..")

import pida

class PIDAModulesListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin):
    '''
    Our custom list control containing loaded pida modules.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES )
        self.top=top

        ListCtrlAutoWidthMixin.__init__(self)

        self.InsertColumn(0,  "# Func")
        self.InsertColumn(1,  "# BB")
        self.InsertColumn(2,  "PIDA Module")


    ####################################################################################################################
    def on_add_module (self, event):
        '''
        Load a PIDA module into memory.
        '''

        dlg = wx.FileDialog(                                    \
            self,                                               \
            message     = "Select PIDA module",                 \
            defaultDir  = os.getcwd(),                          \
            defaultFile = "",                                   \
            wildcard    = "*.PIDA",                             \
            style       = wx.OPEN | wx.CHANGE_DIR | wx.MULTIPLE \
        )

        if dlg.ShowModal() != wx.ID_OK:
            return

        for path in dlg.GetPaths():
            try:
                module_name = path[path.rfind("\\")+1:path.rfind(".pida")].lower()

                if self.top.pida_modules.has_key(module_name):
                    self.top.err("Module %s already loaded ... skipping." % module_name)
                    continue

                # deprecated - replaced by progress dialog.
                #busy = wx.BusyInfo("Loading %s ... stand by." % module_name)
                #wx.Yield()

                start  = time.time()
                module = pida.load(path, progress_bar="wx")

                if not module:
                    self.top.msg("Loading of PIDA module '%s' cancelled by user." % module_name)
                    return

                elif module == -1:
                    raise Exception

                else:
                    self.top.pida_modules[module_name] = module
                    self.top.msg("Loaded PIDA module '%s' in %.2f seconds." % (module_name, round(time.time() - start, 3)))

                # add the function / basic blocks to the global count.
                function_count    = len(self.top.pida_modules[module_name].nodes)
                basic_block_count = 0

                for function in self.top.pida_modules[module_name].nodes.values():
                    basic_block_count += len(function.nodes)

                self.top.function_count    += function_count
                self.top.basic_block_count += basic_block_count

                self.top.update_gauges()

                idx = len(self.top.pida_modules) - 1
                self.InsertStringItem(idx, "")
                self.SetStringItem(idx, 0, "%d" % function_count)
                self.SetStringItem(idx, 1, "%d" % basic_block_count)
                self.SetStringItem(idx, 2, module_name)

                self.SetColumnWidth(2, wx.LIST_AUTOSIZE)
            except:
                self.top.err("FAILED LOADING MODULE: %s. Possibly corrupt or version mismatch?" % module_name)
                if self.top.pida_modules.has_key(module_name):
                    del(self.top.pida_modules[module_name])


    ####################################################################################################################
    def on_right_click (self, event):
        '''
        When an item in the PIDA module list is right clicked, display a context menu.
        '''

        if not self.x or not self.y:
            return

        # we only have to do this once, that is what the hasattr() check is for.
        if not hasattr(self, "right_click_popup_remove"):
            self.right_click_popup_remove = wx.NewId()
            self.Bind(wx.EVT_MENU, self.on_right_click_popup_remove, id=self.right_click_popup_remove)

        # make a menu.
        menu = wx.Menu()
        menu.Append(self.right_click_popup_remove, "Remove")

        self.PopupMenu(menu, (self.x, self.y))
        menu.Destroy()


    ####################################################################################################################
    def on_right_click_popup_remove (self, event):
        '''
        Right click event handler for popup remove menu selection.
        '''

        idx    = self.GetFirstSelected()
        module = self.GetItem(idx, 2).GetText()

        # add the function / basic blocks to the global count.
        self.top.function_count -= len(self.top.pida_modules[module].nodes)

        for function in self.top.pida_modules[module].nodes.values():
            self.top.basic_block_count -= len(function.nodes)

        self.top.update_gauges()

        del(self.top.pida_modules[module])
        self.DeleteItem(idx)


    ####################################################################################################################
    def on_right_down (self, event):
        '''
        Grab the x/y coordinates when the right mouse button is clicked.
        '''

        self.x = event.GetX()
        self.y = event.GetY()

        item, flags = self.HitTest((self.x, self.y))

        if flags & wx.LIST_HITTEST_ONITEM:
            self.Select(item)
        else:
            self.x = None
            self.y = None
