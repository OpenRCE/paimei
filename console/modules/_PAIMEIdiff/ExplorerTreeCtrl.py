#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: ExplorerTreeCtrl.py 194 2007-04-05 15:31:53Z cameron $
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
import MySQLdb
import sys
import os
import time
import PAIMEIDiffFunction
import pida



class ExplorerTreeCtrl (wx.TreeCtrl):
    '''
    Our custom tree control.
    '''

    def __init__ (self, parent, id, pos=None, size=None, style=None, top=None, name=None):
        wx.TreeCtrl.__init__(self, parent, id, pos, size, style)
        self.top            = top
        self.selected       = None
        self.module_name    = ""
        
        self.ctrl_name = name
        
        # setup our custom tree list control.
        self.icon_list        = wx.ImageList(16, 16)
        self.icon_folder      = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER,      wx.ART_OTHER, (16, 16)))
        self.icon_folder_open = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER_OPEN, wx.ART_OTHER, (16, 16)))
        self.icon_tag         = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_NORMAL_FILE, wx.ART_OTHER, (16, 16)))
        self.icon_selected    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FIND,        wx.ART_OTHER, (16, 16)))
        self.icon_filtered    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_CUT,         wx.ART_OTHER, (16, 16)))

        self.SetImageList(self.icon_list)

        self.root = self.AddRoot("Modules")
        self.root_module = None
        self.SetPyData(self.root, None)
        self.SetItemImage(self.root, self.icon_folder,      wx.TreeItemIcon_Normal)
        self.SetItemImage(self.root, self.icon_folder_open, wx.TreeItemIcon_Expanded)



    ####################################################################################################################
    def load_module (self, module_name):
        '''
        Load the specified module into the tree.
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

            module_name = path[path.rfind("\\")+1:path.rfind(".pida")].lower()
            
            if self.top.pida_modules.has_key(module_name):
                self.top.err("Module %s already loaded ... skipping." % module_name)
                continue
    
            busy = wx.BusyInfo("Loading module ... stand by.")
            wx.Yield()
            
            start = time.time()
       
            #if they want to diff a new module remove the current module
            if self.root_module != None:
                del self.top.pida_modules[self.module_name]
                self.remove_module()
                
            self.top.pida_modules[module_name] = pida.load(path)
            
            #if we are tree a then we load the module name into module_a_name and visa versa
            if self.ctrl_name == "A":
                self.top.module_a_name = module_name
            else:
                self.top.module_b_name = module_name
                
            #set the current module name
            self.module_name = module_name
            
            tree_module = self.AppendItem(self.root, module_name)
            
            self.root_module = tree_module
            
            self.SetPyData(tree_module, self.top.pida_modules[module_name])
            self.SetItemImage(tree_module, self.icon_folder,      wx.TreeItemIcon_Normal)
            self.SetItemImage(tree_module, self.icon_folder_open, wx.TreeItemIcon_Expanded)
        
            sorted_functions = [f.id for f in self.top.pida_modules[module_name].nodes.values() if not f.is_import]
            sorted_functions.sort()
        
            for func_key in sorted_functions:
                #add our extension into the loaded module
                self.top.pida_modules[module_name].nodes[func_key].ext["PAIMEIDiffFunction"] = PAIMEIDiffFunction.PAIMEIDiffFunction(self.top.pida_modules[module_name].nodes[func_key], self.top.pida_modules[module_name], self.top)
                function = self.top.pida_modules[module_name].nodes[func_key]
                tree_function = self.AppendItem(tree_module, "%08x - %s" % (function.ea_start, function.name))
                self.SetPyData(tree_function, self.top.pida_modules[module_name].nodes[func_key])
                self.SetItemImage(tree_function, self.icon_folder,      wx.TreeItemIcon_Normal)
                self.SetItemImage(tree_function, self.icon_folder_open, wx.TreeItemIcon_Expanded)
                
                sorted_bbs = function.nodes.keys()
                sorted_bbs.sort()
        

            self.Expand(self.root)
            self.top.msg("Loaded %d function(s) in PIDA module '%s' in %.2f seconds." % (len(self.top.pida_modules[module_name].nodes), module_name, round(time.time() - start, 3)))
                
               
            
    ####################################################################################################################
    def remove_module (self):
        '''
        Remove the module from the TreeCtrl
        '''
        if not self.root_module:
            return
            
        self.DeleteChildren(self.root_module)
        self.Delete(self.root_module)    
                  

