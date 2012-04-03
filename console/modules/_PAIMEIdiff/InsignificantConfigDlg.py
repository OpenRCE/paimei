#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: InsignificantConfigDlg.py 194 2007-04-05 15:31:53Z cameron $
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
import re
# begin wxGlade: dependencies
# end wxGlade

class InsignificantConfigDlg(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]
        # begin wxGlade: InsignificantConfigDlg.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.sizer_20_staticbox = wx.StaticBox(self, -1, "Insignificant Basic Block")
        self.sizer_19_staticbox = wx.StaticBox(self, -1, "Insignificant Function")
        self.label_1 = wx.StaticText(self, -1, "Function Definition should look like a NECI. \n(Num Nodes: Num Edges: Num Calls: Num Instructions) \ndefault is 1:1:1:1")
        s = "%s:%s:%s:%s" % self.parent.parent.insignificant_function
        self.FuncTxtCtrl = wx.TextCtrl(self, -1, s)
        self.label_2 = wx.StaticText(self, -1, "Basic Block definition is only the instruction count. \nDefault is 2. ")
        self.BBTxtCtrl  = wx.TextCtrl(self, -1, str(self.parent.parent.insignificant_bb))
        self.DoneButton = wx.Button(self, -1, "Done")
        self.CancelButton = wx.Button(self, -1, "Cancel")

        self.__set_properties()
        self.__do_layout()
        # end wxGlade
        self.function_def = self.parent.parent.insignificant_function
        self.bb_def       = self.parent.parent.insignificant_bb
        
        self.Bind(wx.EVT_BUTTON,         self.on_done,          self.DoneButton)
        self.Bind(wx.EVT_BUTTON,         self.on_cancel,        self.CancelButton)

    def __set_properties(self):
        # begin wxGlade: InsignificantConfigDlg.__set_properties
        self.SetTitle("Insignificant Function/BB Configuration")
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: InsignificantConfigDlg.__do_layout
        sizer_17 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_18 = wx.BoxSizer(wx.VERTICAL)
        sizer_22 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_20 = wx.StaticBoxSizer(self.sizer_20_staticbox, wx.HORIZONTAL)
        sizer_21 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_19 = wx.StaticBoxSizer(self.sizer_19_staticbox, wx.HORIZONTAL)
        sizer_19.Add(self.label_1, 0, wx.ADJUST_MINSIZE, 0)
        sizer_19.Add(self.FuncTxtCtrl, 0, wx.ADJUST_MINSIZE, 0)
        sizer_18.Add(sizer_19, 1, wx.EXPAND, 0)
        sizer_21.Add(self.label_2, 0, wx.ADJUST_MINSIZE, 0)
        sizer_21.Add(self.BBTxtCtrl, 0, wx.ADJUST_MINSIZE, 0)
        sizer_20.Add(sizer_21, 1, wx.EXPAND, 0)
        sizer_18.Add(sizer_20, 1, wx.EXPAND, 0)
        sizer_22.Add(self.DoneButton, 0, wx.ADJUST_MINSIZE, 0)
        sizer_22.Add(self.CancelButton, 0, wx.ADJUST_MINSIZE, 0)
        sizer_18.Add(sizer_22, 1, wx.EXPAND, 0)
        sizer_17.Add(sizer_18, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_17)
        sizer_17.Fit(self)
        sizer_17.SetSizeHints(self)
        self.Layout()
        # end wxGlade
    
    ####################################################################################################################
    def on_done(self, event):
        func = self.FuncTxtCtrl.GetValue()
        bb = self.BBTxtCtrl.GetValue()
        

        try:
            bb_i = int(bb)
        except:
            self.parent.parent.err("%s is not an integer reverting to default" % bb)
            bb_i = 2
            
        if bb_i < 0:
            self.parent.parent.err("%d is a negative reverting to default" % bb_i)
            bb_i = 2        

        
        x = func.split(":")
        p = re.compile("(\d+):(\d+):(\d+):(\d+)")
        m = p.match(func)
        if not m:
            self.parent.parent.err("Failed to parse %s reverting to default" % func)
        else:
            try:
                func_i = (int(x[0]), int(x[1]), int(x[2]), int(x[3]))
            except:
                self.parent.parent.err("%s is not an integer reverting to default" % func)
                func_i = (1,1,1,1)
        
        self.parent.parent.insignificant_function = func_i
        self.parent.parent.insignificant_bb = bb_i
        self.Destroy()

    ####################################################################################################################
    def on_cancel(self,event):
        self.Destroy()
    
# end of class InsignificantConfigDlg
    

