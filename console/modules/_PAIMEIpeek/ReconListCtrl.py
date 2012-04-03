#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: ReconListCtrl.py 194 2007-04-05 15:31:53Z cameron $
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

import MySQLdb
import time

import _PAIMEIpeek

class ReconListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin, ColumnSorterMixin):
    '''
    Our custom list control containing the various recon points and relevant notes.
    '''

    def __init__(self, parent, id, pos=None, size=None, style=None, top=None):
        wx.ListCtrl.__init__(self, parent, id, style=style)
        self.parent  = parent
        self.top     = top

        ListCtrlAutoWidthMixin.__init__(self)

        self.items_sort_map = {}
        self.itemDataMap    = self.items_sort_map

        ColumnSorterMixin.__init__(self, 8)

        self.InsertColumn(0, "ID")
        self.InsertColumn(1, "Address")
        self.InsertColumn(2, "Depth")
        self.InsertColumn(3, "Status")
        self.InsertColumn(4, "Username")
        self.InsertColumn(5, "# Hits")
        self.InsertColumn(6, "Boron Tag")
        self.InsertColumn(7, "Reason")


    ####################################################################################################################
    def GetListCtrl (self):
        '''
        Used by the ColumnSorterMixin, see wx/lib/mixins/listctrl.py
        '''

        return self


    ####################################################################################################################
    def load (self, id):
        self.DeleteAllItems()

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        try:
            busy = wx.BusyInfo("Loading... please wait.")
            wx.Yield()
        except:
            pass

        # instantiate a mysql cursor.
        cursor = mysql.cursor(MySQLdb.cursors.DictCursor)

        # retrieve the module info.
        cursor.execute("SELECT * FROM pp_modules WHERE id = '%d'" % id)
        module = cursor.fetchone()

        # save the selected module DB entry to the top.
        self.top.module = module

        # step through the recon entries for this module id.
        cursor.execute("SELECT * FROM pp_recon WHERE module_id = '%d' ORDER BY offset ASC" % id)

        idx = reviewed = 0
        for recon in cursor.fetchall():
            address = module["base"] + recon["offset"]

            # count the number of hits under this recon point.
            c = mysql.cursor(MySQLdb.cursors.DictCursor)
            c.execute("SELECT COUNT(id) AS count FROM pp_hits WHERE recon_id = '%d'" % recon["id"])
            num_hits = c.fetchone()["count"]
            c.close()

            self.InsertStringItem(idx, "")
            self.SetStringItem(idx, 0, "%04x" % recon["id"])
            self.SetStringItem(idx, 1, "%08x" % address)
            self.SetStringItem(idx, 2, "%d" % recon["stack_depth"])
            self.SetStringItem(idx, 3, recon["status"])
            self.SetStringItem(idx, 4, recon["username"])
            self.SetStringItem(idx, 5, "%d" % num_hits)
            self.SetStringItem(idx, 6, recon["boron_tag"])
            self.SetStringItem(idx, 7, recon["reason"])

            # create an entry for the column sort map.
            self.SetItemData(idx, idx)
            self.items_sort_map[idx] = (recon["id"], address, recon["stack_depth"], recon["status"], recon["username"], num_hits, recon["boron_tag"], recon["reason"])

            if recon["status"] in ["uncontrollable", "clear", "vulnerable"]:
                reviewed += 1

            idx += 1

        # update % coverage gauge.
        self.top.percent_analyzed_static.SetLabel("%d of %d RECON Points Reviewed:" % (reviewed, idx))
        percent = int((float(reviewed) / float(idx)) * 100)
        self.top.percent_analyzed.SetValue(percent)

        cursor.close()


    ####################################################################################################################
    def on_activated (self, event):
        '''
        Load the PIDA module into the browser tree ctrl.
        '''

        recon_id = long(self.GetItem(event.m_itemIndex, 0).GetText(), 16)
        dlg      = _PAIMEIpeek.EditReconDlg.EditReconDlg(parent=self)

        dlg.propagate(recon_id)
        dlg.ShowModal()


    ####################################################################################################################
    def on_right_click (self, event):
        '''
        When an item in the recon list is right clicked, display a context menu.
        '''

        if not self.x or not self.y:
            return

        # we only have to do this once, that is what the hasattr() check is for.
        if not hasattr(self, "right_click_popup_refresh"):
            self.right_click_popup_refresh     = wx.NewId()
            self.right_click_popup_edit        = wx.NewId()
            self.right_click_popup_self_assign = wx.NewId()
            self.right_click_popup_delete      = wx.NewId()

            self.Bind(wx.EVT_MENU, self.on_right_click_popup_refresh,     id=self.right_click_popup_refresh)
            self.Bind(wx.EVT_MENU, self.on_right_click_popup_edit,        id=self.right_click_popup_edit)
            self.Bind(wx.EVT_MENU, self.on_right_click_popup_self_assign, id=self.right_click_popup_self_assign)
            self.Bind(wx.EVT_MENU, self.on_right_click_popup_delete,      id=self.right_click_popup_delete)

        # make a menu.
        menu = wx.Menu()
        menu.Append(self.right_click_popup_refresh, "&Refresh List")
        menu.AppendSeparator()
        menu.Append(self.right_click_popup_edit, "&Edit Recon Point")
        menu.Append(self.right_click_popup_self_assign, "Assign to &Self")
        menu.AppendSeparator()
        menu.Append(self.right_click_popup_delete, "Delete")

        self.PopupMenu(menu, (self.x, self.y))
        menu.Destroy()


    ####################################################################################################################
    def on_right_click_popup_delete (self, event):
        '''
        Right click event handler for popup delete menu selection.
        '''

        recon_id = self.selected_id

        # make sure the user is sure about this action.
        dlg = wx.MessageDialog(self, 'Delete the selected recon point?', 'Are you sure?', wx.YES_NO | wx.ICON_QUESTION)

        if dlg.ShowModal() != wx.ID_YES:
            return

        cursor = self.top.main_frame.mysql.cursor()
        cursor.execute("DELETE FROM pp_recon WHERE id = '%d'" % recon_id)
        cursor.close()

        # reload the recon list control. we reload instead of updating the control to partially solve
        # contention issues when multiple users are hitting the database at the same time.
        self.load(self.top.module["id"])

    ####################################################################################################################
    def on_right_click_popup_edit (self, event):
        '''
        Right click event handler for popup edit menu selection.
        '''

        recon_id = self.selected_id
        dlg      = _PAIMEIpeek.EditReconDlg.EditReconDlg(parent=self)

        dlg.propagate(recon_id)
        dlg.ShowModal()


    ####################################################################################################################
    def on_right_click_popup_refresh (self, event):
        '''
        Right click event handler for popup refresh list.
        '''

        self.load(self.top.module["id"])


    ####################################################################################################################
    def on_right_click_popup_self_assign (self, event):
        '''
        Right click event handler for popup assign item to self selection.
        '''

        if not self.top.main_frame.username:
            self.top.err("You must tell PaiMei who you are first.")
            return

        cursor   = self.top.main_frame.mysql.cursor()
        recon_id = self.selected_id

        cursor.execute("UPDATE pp_recon SET username = '%s' WHERE id = '%d'" % (self.top.main_frame.username, recon_id))

        # reload the recon list control. we reload instead of updating the control to partially solve
        # contention issues when multiple users are hitting the database at the same time.
        self.load(self.top.module["id"])


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


    ####################################################################################################################
    def on_select (self, event):
        '''
        A line item in the recon list control was selected, load the hits list.
        '''

        recon_id         = long(self.GetItem(event.m_itemIndex, 0).GetText(), 16)
        self.selected_id = recon_id

        # clear the hit list control.
        self.top.hit_list.Set("")

        # load the list of hits for this recon_id.
        # select DESC so when we insert it re-sorts to ASC.
        try:
            cursor = self.top.main_frame.mysql.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT id, timestamp FROM pp_hits WHERE recon_id = '%d' ORDER BY timestamp, id DESC" % recon_id)
        except:
            self.top.err("MySQL query failed. Connection dropped?")
            return

        hit = False
        for hit in cursor.fetchall():
            timestamp = time.strftime("%m/%d/%Y %H:%M.%S", time.localtime(hit["timestamp"]))

            # timestamps are returned from the DB in reverse order and placed in ASC order by this command.
            self.top.hit_list.Insert(timestamp, 0)

            # associate the needed ID with this inserted item.
            self.top.hit_list.SetClientData(0, hit["id"])

        # select the first entry in the hit list.
        if hit:
            self.top.on_hit_list_select(None, hit["id"])
            self.top.hit_list.Select(0)
        else:
            self.top.peek_data.SetValue("")