#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PAIMEIdocs.py 231 2008-07-21 22:43:36Z pedram.amini $
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
import wx.html as html

class PAIMEIdocs(wx.Panel):
    '''
    '''

    sections = {
                   "General":   "../docs/index.html",
                   "PyDbg":     "../docs/PyDBG/class-tree.html",
                   "PIDA":      "../docs/PIDA/class-tree.html",
                   "pGRAPH":    "../docs/pGRAPH/class-tree.html",
                   "Utilities": "../docs/Utilities/class-tree.html",
               }

    list_book  = None     # handle to list book.
    main_frame = None     # handle to top most frame.
    selection  = None     # selected help section.

    def __init__ (self, *args, **kwds):
        self.choices = self.sections.keys()
        self.choices.sort()

        # begin wxGlade: PAIMEIdocs.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)
        self.navigation_staticbox = wx.StaticBox(self, -1, "Navigate")
        self.section_dropdown     = wx.Choice(self, -1, choices=self.choices)
        self.load                 = wx.Button(self, -1, "Load")
        self.back                 = wx.Button(self, -1, "Back")
        self.forward              = wx.Button(self, -1, "Forward")
        self.html_help            = html.HtmlWindow(self, -1)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        self.list_book  = kwds["parent"]            # handle to list book.
        self.main_frame = self.list_book.top        # handle to top most frame.

        # bind the dropdown.
        self.Bind(wx.EVT_CHOICE, self.on_section_choice, self.section_dropdown)

        # bind the buttons
        self.Bind(wx.EVT_BUTTON, self.on_back,    self.back)
        self.Bind(wx.EVT_BUTTON, self.on_forward, self.forward)
        self.Bind(wx.EVT_BUTTON, self.on_load,    self.load)

        # load the default top-level documentation page.
        self.html_help.LoadPage(self.sections["General"])


    ####################################################################################################################
    def __set_properties (self):
        # begin wxGlade: PAIMEIdocs.__set_properties
        self.section_dropdown.SetSelection(-1)
        # end wxGlade


    ####################################################################################################################
    def __do_layout (self):
        # begin wxGlade: PAIMEIdocs.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        navigation = wx.StaticBoxSizer(self.navigation_staticbox, wx.HORIZONTAL)
        navigation.Add(self.section_dropdown, 0, wx.ADJUST_MINSIZE, 0)
        navigation.Add(self.load, 0, wx.ADJUST_MINSIZE, 0)
        navigation.Add(self.back, 0, wx.ADJUST_MINSIZE, 0)
        navigation.Add(self.forward, 0, wx.ADJUST_MINSIZE, 0)
        overall.Add(navigation, 0, wx.EXPAND, 0)
        overall.Add(self.html_help, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        # end wxGlade


    ####################################################################################################################
    def on_back (self, event):
        self.html_help.HistoryBack()


    ####################################################################################################################
    def on_forward (self, event):
        self.html_help.HistoryForward()


    ####################################################################################################################
    def on_load (self, event):
        if not self.selection:
            return

        self.html_help.LoadPage(self.main_frame.cwd + "/" + self.sections[self.selection])


    ####################################################################################################################
    def on_section_choice (self, event):
        self.selection = event.GetString()
