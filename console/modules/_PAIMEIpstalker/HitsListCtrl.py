#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: HitsListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
import MySQLdb
import time

from wx.lib.mixins.listctrl import ColumnSorterMixin
from wx.lib.mixins.listctrl import ListCtrlAutoWidthMixin

class HitsListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin, ColumnSorterMixin):
    '''
    Our custom list control containing the hits for the current target/tag.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT | wx.SIMPLE_BORDER | wx.LC_HRULES )
        self.top           = top
        self.hits_by_index = {}
        self.eips          = []
        self.last_focused  = None

        ListCtrlAutoWidthMixin.__init__(self)

        self.items_sort_map = {}
        self.itemDataMap    = self.items_sort_map

        ColumnSorterMixin.__init__(self, 7)

        self.InsertColumn(0, "#")
        self.InsertColumn(1, "Time")
        self.InsertColumn(2, "EIP")
        self.InsertColumn(3, "TID")
        self.InsertColumn(4, "Module")
        self.InsertColumn(5, "Func?")
        self.InsertColumn(6, "Tag")


    ####################################################################################################################
    def append_hits (self, tag_id):
        '''
        '''

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        busy = wx.BusyInfo("Loading... please wait.")
        wx.Yield()

        # step through the hits for this tag id.
        hits = mysql.cursor(MySQLdb.cursors.DictCursor)
        hits.execute("SELECT hits.*, tags.tag FROM cc_hits AS hits, cc_tags AS tags WHERE hits.tag_id = '%d' AND tags.id = '%d' ORDER BY num ASC" % (tag_id, tag_id))

        idx      = len(self.hits_by_index)
        hitlist  = hits.fetchall()

        # XXX - need to fix this logic, it craps out some times
        try:
            min_time = min([h["timestamp"] for h in hitlist if h["timestamp"] != 0])
        except:
            min_time = 0

        for hit in hitlist:
            self.hits_by_index[idx] = hit

            if self.eips.count(hit["eip"]) == 0:
                if hit["is_function"]:
                    self.top.hit_function_count += 1

                self.top.hit_basic_block_count += 1

            if hit["is_function"]: is_function = "Y"
            else:                  is_function = ""

            timestamp = int(hit["timestamp"]) - min_time

            self.InsertStringItem(idx, "")
            self.SetStringItem(idx, 0, "%d"   % hit["num"])
            self.SetStringItem(idx, 1, "+%ds" % timestamp)
            self.SetStringItem(idx, 2, "%08x" % hit["eip"])
            self.SetStringItem(idx, 3, "%d"   % hit["tid"])
            self.SetStringItem(idx, 4,          hit["module"])
            self.SetStringItem(idx, 5, "%s"   % is_function)
            self.SetStringItem(idx, 6,          hit["tag"])

            self.items_sort_map[idx] = ( \
                int(hit["num"]),
                "+%ds" % timestamp,
                "%08x" % hit["eip"],
                int(hit["tid"]),
                hit["module"],
                "%s"   % is_function,
                hit["tag"])

            self.SetItemData(idx, idx)

            self.eips.append(hit["eip"])
            idx += 1

        self.top.update_gauges()


    ####################################################################################################################
    def focus_item_by_address (self, address):
        '''
        '''

        # find the first occurence of address in the list and set the focus on it.
        for (idx, hit) in self.hits_by_index.items():
            if hit["eip"] == address:
                state = state_mask = wx.LIST_STATE_FOCUSED | wx.LIST_STATE_SELECTED
                self.SetItemState(idx, state, state_mask)
                self.EnsureVisible(idx)

                if self.last_focused:
                    self.SetItemState(self.last_focused, 0, state_mask)

                self.last_focused = idx
                break


    ####################################################################################################################
    def GetListCtrl (self):
        '''
        Used by the ColumnSorterMixin, see wx/lib/mixins/listctrl.py
        '''

        return self


    ####################################################################################################################
    def load_hits (self, tag_id):
        '''
        '''

        # reset the global counters.
        self.top.hit_function_count    = 0
        self.top.hit_basic_block_count = 0

        # reset the hits by index dictionary and hit eip cache.
        self.hits_by_index = {}
        self.eips          = []

        # clear the list.
        self.DeleteAllItems()

        self.append_hits(tag_id)


    ####################################################################################################################
    def on_select (self, event):
        self.selected = event.GetItem()

        hit = self.hits_by_index[self.GetItemData(self.selected.GetId())]

        separator = "-" * 72

        context_dump  = "%s\n" % time.ctime(hit["timestamp"])
        context_dump += "EIP: %08x\n" % hit["eip"]
        context_dump += "EAX: %08x (%10d) -> %s\n" % (hit["eax"], hit["eax"], hit["eax_deref"])
        context_dump += "EBX: %08x (%10d) -> %s\n" % (hit["ebx"], hit["ebx"], hit["ebx_deref"])
        context_dump += "ECX: %08x (%10d) -> %s\n" % (hit["ecx"], hit["ecx"], hit["ecx_deref"])
        context_dump += "EDX: %08x (%10d) -> %s\n" % (hit["edx"], hit["edx"], hit["edx_deref"])
        context_dump += "EDI: %08x (%10d) -> %s\n" % (hit["edi"], hit["edi"], hit["edi_deref"])
        context_dump += "ESI: %08x (%10d) -> %s\n" % (hit["esi"], hit["esi"], hit["esi_deref"])
        context_dump += "EBP: %08x (%10d) -> %s\n" % (hit["ebp"], hit["ebp"], hit["ebp_deref"])
        context_dump += "ESP: %08x (%10d) -> %s\n" % (hit["esp"], hit["esp"], hit["esp_deref"])

        context_dump += "+04: %08x (%10d) -> %s\n" % (hit["esp_4"],  hit["esp_4"],  hit["esp_4_deref"])
        context_dump += "+08: %08x (%10d) -> %s\n" % (hit["esp_8"],  hit["esp_8"],  hit["esp_8_deref"])
        context_dump += "+0C: %08x (%10d) -> %s\n" % (hit["esp_c"],  hit["esp_c"],  hit["esp_c_deref"])
        context_dump += "+10: %08x (%10d) -> %s\n" % (hit["esp_10"], hit["esp_10"], hit["esp_10_deref"])

        self.top.hit_details.SetValue(context_dump)

        # if a udraw connection is available, bring the selected node into focus.
        self.top.targets.udraw_focus_node_by_address(hit["eip"])