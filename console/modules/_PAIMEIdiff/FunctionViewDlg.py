#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: FunctionViewDlg.py 194 2007-04-05 15:31:53Z cameron $
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
import FunctionViewListCtrl
import FunctionViewStatsListCtrl

# begin wxGlade: dependencies
# end wxGlade

class FunctionViewDlg(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: FunctionViewDlg.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.parent = kwds["parent"]
        self.FunctionViewListCtrl = FunctionViewListCtrl.FunctionViewListCtrl(self, -1, top=self.parent, style=wx.LC_REPORT|wx.SUNKEN_BORDER | wx.LC_SINGLE_SEL )
        self.FunctionViewStatsListCtrl = FunctionViewStatsListCtrl.FunctionViewStatsListCtrl(self, -1, style=wx.LC_REPORT|wx.SUNKEN_BORDER, name="U",top=self.parent)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade
        self.FunctionViewListCtrl.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.FunctionViewListCtrl.OnRightClick)
        self.FunctionViewListCtrl.Bind(wx.EVT_LIST_ITEM_SELECTED, self.FunctionViewListCtrl.OnItemSelect)


    def __set_properties(self):
        # begin wxGlade: FunctionViewDlg.__set_properties
        self.SetTitle("Function View")
        self.SetSize((761, 466))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: FunctionViewDlg.__do_layout
        sizer_14 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_15 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_16 = wx.BoxSizer(wx.VERTICAL)
        sizer_16.Add(self.FunctionViewListCtrl, 1, wx.EXPAND, 0)
        sizer_16.Add(self.FunctionViewStatsListCtrl, 1, wx.EXPAND, 0)
        sizer_15.Add(sizer_16, 1, wx.EXPAND, 0)
        sizer_14.Add(sizer_15, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_14)
        self.Layout()
        # end wxGlade

# end of class FunctionViewDlg


