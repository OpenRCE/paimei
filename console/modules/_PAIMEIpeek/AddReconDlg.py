#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: AddReconDlg.py 194 2007-04-05 15:31:53Z cameron $
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
import wx.lib.dialogs
import MySQLdb

class AddReconDlg (wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: AddRecon.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.stack_depth_static_staticbox = wx.StaticBox(self, -1, "Stack Depth:")
        self.reason_static_staticbox = wx.StaticBox(self, -1, "Reason:")
        self.notes_sizer_staticbox = wx.StaticBox(self, -1, "Notes:")
        self.address_static_staticbox = wx.StaticBox(self, -1, "Address:")
        self.address = wx.TextCtrl(self, -1, "")
        self.stack_depth = wx.SpinCtrl(self, -1, "3", min=0, max=99)
        self.reason = wx.TextCtrl(self, -1, "")
        self.notes = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE|wx.HSCROLL)
        self.save = wx.Button(self, -1, "Save")
        self.cancel = wx.Button(self, wx.ID_CANCEL)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        self.Bind(wx.EVT_BUTTON, self.on_button_save, self.save)


    def __set_properties(self):
        # begin wxGlade: AddRecon.__set_properties
        self.SetTitle("Add Recon Point")
        self.SetSize((500, 400))
        self.notes.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        # end wxGlade


    def __do_layout(self):
        # begin wxGlade: AddRecon.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        buttons_sizer = wx.BoxSizer(wx.HORIZONTAL)
        notes_sizer = wx.StaticBoxSizer(self.notes_sizer_staticbox, wx.HORIZONTAL)
        reason_static = wx.StaticBoxSizer(self.reason_static_staticbox, wx.HORIZONTAL)
        stack_depth_static = wx.StaticBoxSizer(self.stack_depth_static_staticbox, wx.HORIZONTAL)
        address_static = wx.StaticBoxSizer(self.address_static_staticbox, wx.HORIZONTAL)
        address_static.Add(self.address, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(address_static, 1, wx.EXPAND, 0)
        stack_depth_static.Add(self.stack_depth, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(stack_depth_static, 1, wx.EXPAND, 0)
        reason_static.Add(self.reason, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(reason_static, 1, wx.EXPAND, 0)
        notes_sizer.Add(self.notes, 3, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(notes_sizer, 4, wx.EXPAND, 0)
        buttons_sizer.Add(self.save, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        buttons_sizer.Add(self.cancel, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(buttons_sizer, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        self.Layout()
        # end wxGlade


    ####################################################################################################################
    def on_button_save (self, event):
        '''
        Grab the form values and add a new entry to the database.
        '''

        try:
            address = long(self.address.GetLineText(0), 16)
        except:
            dlg = wx.MessageDialog(self, "Invalid 'address' value, expecting a DWORD. Ex: 0xdeadbeef", "Error", wx.OK | wx.ICON_WARNING)
            dlg.ShowModal()
            return

        try:
            stack_depth = int(self.stack_depth.GetValue())
        except:
            dlg = wx.MessageDialog(self, "Must specify an integer for 'stack depth'.", "Error", wx.OK | wx.ICON_WARNING)
            dlg.ShowModal()
            return

        reason = self.reason.GetLineText(0)
        notes  = self.notes.GetValue()

        # must at least have a reason. notes are optional.
        if not reason:
            dlg = wx.MessageDialog(self, "Must specify a 'reason'.", "Error", wx.OK | wx.ICON_WARNING)
            dlg.ShowModal()
            return

        sql  = " INSERT INTO pp_recon"
        sql += " SET module_id   = '%d',"  % self.parent.module["id"]
        sql += "     offset      = '%d',"  % (address - self.parent.module["base"])
        sql += "     stack_depth = '%d',"  % stack_depth
        sql += "     reason      = '%s',"  % reason.replace("\\", "\\\\").replace("'", "\\'")
        sql += "     status      = 'new',"
        sql += "     username    = '%s',"  % self.parent.main_frame.username
        sql += "     notes       = '%s'"   % notes.replace("\\", "\\\\").replace("'", "\\'")

        cursor = self.parent.main_frame.mysql.cursor()

        try:
            cursor.execute(sql)
        except MySQLdb.Error, e:
            msg  = "MySQL error %d: %s\n" % (e.args[0], e.args[1])
            msg += sql
            dlg = wx.lib.dialogs.ScrolledMessageDialog(self, msg, "Failed Adding RECON Point")
            dlg.ShowModal()
            return

        # reload the recon list control. we reload instead of updating the control to partially solve
        # contention issues when multiple users are hitting the database at the same time.
        self.parent.recon.load(self.parent.module["id"])
        self.Destroy()