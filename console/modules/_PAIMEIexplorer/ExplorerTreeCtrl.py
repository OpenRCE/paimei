#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: ExplorerTreeCtrl.py 193 2007-04-05 13:30:01Z cameron $
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
import re
import MySQLdb

import pida

class ExplorerTreeCtrl (wx.TreeCtrl):
    '''
    Our custom tree control.
    '''

    def __init__ (self, parent, id, pos=None, size=None, style=None, top=None):
        wx.TreeCtrl.__init__(self, parent, id, pos, size, style)
        self.top            = top
        self.selected       = None
        self.used_for_stalk = None

        # setup our custom tree list control.
        self.icon_list        = wx.ImageList(16, 16)
        self.icon_folder      = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER,      wx.ART_OTHER, (16, 16)))
        self.icon_folder_open = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER_OPEN, wx.ART_OTHER, (16, 16)))
        self.icon_tag         = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_NORMAL_FILE, wx.ART_OTHER, (16, 16)))
        self.icon_selected    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FIND,        wx.ART_OTHER, (16, 16)))
        self.icon_filtered    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_CUT,         wx.ART_OTHER, (16, 16)))

        self.SetImageList(self.icon_list)

        self.root = self.AddRoot("Modules")
        self.SetPyData(self.root, None)
        self.SetItemImage(self.root, self.icon_folder,      wx.TreeItemIcon_Normal)
        self.SetItemImage(self.root, self.icon_folder_open, wx.TreeItemIcon_Expanded)


    ####################################################################################################################
    def on_item_activated (self, event):
        '''
        Make record of the selected target/tag combination.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)

        # module selected.
        if type(selected) == pida.module:
            pass

        # function selected.
        elif type(selected) == pida.function:
            disasm = """
            <html>
                <body text=#eeeeee bgcolor=#000000>
                <font size=4><b>%s</b></font>
                <font face=courier size=2>
            """ % (selected.name)

            for bb in selected.sorted_nodes():
                disasm += "<p>"

                # chunked block.
                if selected.ea_start > bb.ea_start > selected.ea_end:
                    disasm += "<font color=blue>CHUNKED BLOCK --------------------</font><br>"

                for ins in bb.sorted_instructions():
                    ins_disasm = ins.disasm
                    ins_disasm = re.sub("(?P<op>^j..?)\s", "<font color=yellow>\g<op> </font>", ins_disasm)
                    ins_disasm = re.sub("(?P<op>^call)\s", "<font color=red>\g<op> </font>",    ins_disasm)

                    disasm += "<font color=#999999>%08x</font>&nbsp;&nbsp;%s<br>" % (ins.ea, ins_disasm)

            disasm += "</font></body></html>"

            self.top.disassembly.SetPage(disasm)

        # basic block selected.
        elif type(selected) == pida.basic_block:
            pass


    ####################################################################################################################
    def on_item_right_click (self, event):
        if not self.selected:
            return

        if not self.x or not self.y:
            return

        selected = self.GetPyData(self.selected)

        ###
        ### root node.
        ###

        if selected == None:
            return

        ###
        ### module node.
        ###

        elif type(selected) == pida.module:
            # we only have to do this once, that is what the hasattr() check is for.
            if not hasattr(self, "right_click_popup_remove_module"):
                self.right_click_popup_remove_module = wx.NewId()

                self.Bind(wx.EVT_MENU, self.on_right_click_popup_remove_module, id=self.right_click_popup_remove_module)

            # make a menu.
            menu = wx.Menu()
            menu.Append(self.right_click_popup_remove_module, "Remove Module")

            self.PopupMenu(menu, (self.x, self.y))
            menu.Destroy()

        ###
        ### function node.
        ###

        elif type(selected) == pida.function:
            # we only have to do this once, that is what the hasattr() check is for.
            if not hasattr(self, "right_click_popup_graph_function"):
                self.right_click_popup_graph_function = wx.NewId()

                self.Bind(wx.EVT_MENU, self.on_right_click_popup_graph_function, id=self.right_click_popup_graph_function)

            # make a menu.
            menu = wx.Menu()
            menu.Append(self.right_click_popup_graph_function, "Graph Function")

            self.PopupMenu(menu, (self.x, self.y))
            menu.Destroy()

        ###
        ### basic block node.
        ###

        elif type(selected) == pida.function:
            return


    ####################################################################################################################
    def on_item_right_down (self, event):
        '''
        Grab the x/y coordinates when the right mouse button is clicked.
        '''

        self.x = event.GetX()
        self.y = event.GetY()

        item, flags = self.HitTest((self.x, self.y))

        if flags & wx.TREE_HITTEST_ONITEM:
            self.SelectItem(item)
        else:
            self.x = None
            self.y = None


    ####################################################################################################################
    def on_item_sel_changed (self, event):
        '''
        Update the current selected tree control item on every selection change.
        '''

        self.selected = event.GetItem()


    ####################################################################################################################
    def load_module (self, module_name):
        '''
        Load the specified module into the tree.
        '''

        tree_module = self.AppendItem(self.root, module_name)
        self.SetPyData(tree_module, self.top.pida_modules[module_name])
        self.SetItemImage(tree_module, self.icon_folder,      wx.TreeItemIcon_Normal)
        self.SetItemImage(tree_module, self.icon_folder_open, wx.TreeItemIcon_Expanded)

        sorted_functions = [f.ea_start for f in self.top.pida_modules[module_name].nodes.values() if not f.is_import]
        sorted_functions.sort()

        for func_key in sorted_functions:
            function = self.top.pida_modules[module_name].nodes[func_key]
            
            tree_function = self.AppendItem(tree_module, "%08x - %s" % (function.ea_start, function.name))
            self.SetPyData(tree_function, self.top.pida_modules[module_name].nodes[func_key])
            self.SetItemImage(tree_function, self.icon_folder,      wx.TreeItemIcon_Normal)
            self.SetItemImage(tree_function, self.icon_folder_open, wx.TreeItemIcon_Expanded)

            sorted_bbs = function.nodes.keys()
            sorted_bbs.sort()

            for bb_key in sorted_bbs:
                bb = function.nodes[bb_key]

                tree_bb = self.AppendItem(tree_function, "%08x" % bb.ea_start)
                self.SetPyData(tree_bb, function.nodes[bb_key])
                self.SetItemImage(tree_bb, self.icon_tag, wx.TreeItemIcon_Normal)

        self.Expand(self.root)


    ####################################################################################################################
    def on_right_click_popup_graph_function (self, event):
        '''
        Right click event handler for popup add graph function menu selection.
        '''

        if not self.selected:
            return

        selected  = self.GetPyData(self.selected)
        udraw     = self.top.main_frame.udraw

        if not udraw:
            self.top.err("No available connection to uDraw(Graph) server.")
            return

        try:
            udraw.graph_new(selected)
        except:
            self.top.main_frame.udraw = None
            self.top.err("Connection to uDraw(Graph) server severed.")


    ####################################################################################################################
    def on_right_click_popup_remove_module (self, event):
        '''
        Right click event handler for popup add remove module menu selection.
        '''

        if not self.selected:
            return

        self.DeleteChildren(self.selected)
        self.Delete(self.selected)