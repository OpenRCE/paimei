#
# Paimei Python Console Module
# Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>
#
# $Id: PAIMEIextender.py 194 2007-04-05 15:31:53Z cameron $
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
@author:       Cameron Hotchkies
@license:      GNU General Public License 2.0 or later
@contact:      chotchkies@tippingpoint.com
@organization: www.tippingpoint.com
'''

import wx.py as py
import wx

#######################################################################################################################
class PAIMEIextender(wx.Panel):

    crust = None
    
    def __init__(self, *args, **kwds):
        intro = 'PAIMEI Extender interactive shell. Based on wx.pycrust %s' % py.version.VERSION
    
        wx.Panel.__init__(self, *args, **kwds)
    
        overall_sizer = wx.BoxSizer(wx.HORIZONTAL)        
        
        self.crust = py.crust.Crust(self, intro=intro)
        
        overall_sizer.Add(self.crust, 1, wx.EXPAND, 0)
        
        self.SetSizer(overall_sizer)

    