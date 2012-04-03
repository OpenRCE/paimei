#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: target_properties.py 194 2007-04-05 15:31:53Z cameron $
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

########################################################################################################################
class target_properties (wx.Dialog):
    '''
    View and update the properties of any given target/tag combination.
    '''

    def __init__(self, *args, **kwds):
        self.parent    = kwds["parent"]
        self.top       = kwds["top"]
        self.tag_id    = kwds["tag_id"]
        self.target_id = kwds["target_id"]

        # we remove our added dictionary args as wxDialog will complain about them if we don't.
        del(kwds["top"])
        del(kwds["tag_id"])
        del(kwds["target_id"])

        # ensure a MySQL connection is available.
        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        # begin wxGlade: target_properties.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.target_id_static = wx.StaticText(self, -1, "Target: %d" % self.target_id)
        self.target           = wx.TextCtrl(self, -1, "")
        self.tag_id_static    = wx.StaticText(self, -1, "Tag: %d" % self.tag_id)
        self.tag              = wx.TextCtrl(self, -1, "")
        self.notes_static     = wx.StaticText(self, -1, "Notes:")
        self.notes            = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE)
        self.apply_changes    = wx.Button(self, -1, "Apply Changes")
        self.close            = wx.Button(self, -1, "Cancel")

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        # event handlers.
        self.Bind(wx.EVT_BUTTON, self.on_apply_changes, self.apply_changes)
        self.Bind(wx.EVT_BUTTON, self.on_close,         self.close)

        # initialize the text controls with the most recent content from the database.
        cursor = mysql.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT tags.*, targets.target FROM cc_targets AS targets, cc_tags AS tags WHERE tags.id = '%d' and targets.id = '%d'" % (self.tag_id, self.target_id))
        hit = cursor.fetchall()[0]
        self.target.SetValue("%s" % hit["target"])
        self.tag.SetValue("%s" % hit["tag"])
        self.notes.SetValue("%s" % hit["notes"])


    ####################################################################################################################
    def __set_properties(self):
        # begin wxGlade: target_properties.__set_properties
        self.SetTitle("Target Properties")
        self.SetSize((500, 300))
        self.target.SetFont(wx.Font(9, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Courier New"))
        self.tag.SetFont(wx.Font(9, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Courier New"))
        self.notes.SetFont(wx.Font(9, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Courier New"))
        # end wxGlade


    ####################################################################################################################
    def __do_layout(self):
        # begin wxGlade: target_properties.__do_layout
        sizer_14 = wx.BoxSizer(wx.VERTICAL)
        sizer_15 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_14.Add(self.target_id_static, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(self.target, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(self.tag_id_static, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(self.tag, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(self.notes_static, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(self.notes, 4, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_15.Add(self.apply_changes, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_15.Add(self.close, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        sizer_14.Add(sizer_15, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_14)
        self.Layout()
        # end wxGlade


    ####################################################################################################################
    def on_apply_changes (self, event):
        '''
        Commit changes to database.
        '''

        # ensure a MySQL connection is available.
        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        # grab and SQL sanitize the text fields from the dialog.
        target = self.target.GetLineText(0).replace("\\", "\\\\").replace("'", "\\'")
        tag    = self.tag.GetLineText(0).replace("\\", "\\\\").replace("'", "\\'")
        notes  = self.notes.GetValue().replace("\\", "\\\\").replace("'", "\\'")

        cursor = mysql.cursor()
        cursor.execute("UPDATE cc_targets SET target = '%s' WHERE id = '%d'" % (target, self.target_id))
        cursor.execute("UPDATE cc_tags SET tag = '%s', notes = '%s' WHERE id = '%d' AND target_id = '%d'" % (tag, notes, self.tag_id, self.target_id))

        # refresh the targets list.
        self.parent.on_retrieve_targets(None)

        # close the dialog.
        self.Destroy()


    ####################################################################################################################
    def on_close (self, event):
        '''
        Ignore any changes and close the dialog.
        '''

        self.Destroy()