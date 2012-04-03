#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: TargetsTreeCtrl.py 231 2008-07-21 22:43:36Z pedram.amini $
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
import thread

import export_idc_dialog
import target_properties
import utils
import pgraph

class TargetsTreeCtrl (wx.TreeCtrl):
    '''
    Our custom tree control containing targets and tags from column one.
    '''

    def __init__ (self, parent, id, pos=None, size=None, style=None, top=None):
        wx.TreeCtrl.__init__(self, parent, id, pos, size, style)
        self.top            = top
        self.selected       = None
        self.used_for_stalk = None

        # udraw sync class variables.
        self.cc                   = None
        self.udraw                = None
        self.udraw_last_color     = None
        self.udraw_last_color_id  = None
        self.udraw_last_selected  = None
        self.udraw_base_graph     = None
        self.udraw_current_graph  = None
        self.udraw_hit_funcs      = []
        self.udraw_in_function    = False

        # setup our custom target tree list control.
        self.icon_list        = wx.ImageList(16, 16)
        self.icon_folder      = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER,      wx.ART_OTHER, (16, 16)))
        self.icon_folder_open = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER_OPEN, wx.ART_OTHER, (16, 16)))
        self.icon_tag         = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_NORMAL_FILE, wx.ART_OTHER, (16, 16)))
        self.icon_selected    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_FIND,        wx.ART_OTHER, (16, 16)))
        self.icon_filtered    = self.icon_list.Add(wx.ArtProvider_GetBitmap(wx.ART_CUT,         wx.ART_OTHER, (16, 16)))

        self.SetImageList(self.icon_list)

        self.root = self.AddRoot("Available Targets")
        self.SetPyData(self.root, None)
        self.SetItemImage(self.root, self.icon_folder,      wx.TreeItemIcon_Normal)
        self.SetItemImage(self.root, self.icon_folder_open, wx.TreeItemIcon_Expanded)


    ####################################################################################################################
    def on_right_click_popup_add_tag (self, event):
        '''
        Right click event handler for popup add tag menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)
        mysql    = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        dlg = wx.TextEntryDialog(self, "Enter name of new tag:", "Add Tag", "")

        if dlg.ShowModal() != wx.ID_OK:
            return

        tag_name = dlg.GetValue()
        tag_name = tag_name.replace("\\", "\\\\").replace("'", "\\'")

        new_tag = mysql.cursor()
        new_tag.execute("INSERT INTO cc_tags SET target_id = '%d', tag = '%s', notes = ''" % (selected["id"], tag_name))

        # refresh the targets list.
        self.on_retrieve_targets(None)

        dlg.Destroy()


    ####################################################################################################################
    def on_right_click_popup_add_target (self, event):
        '''
        Right click event handler for popup add target menu selection.
        '''

        if not self.selected:
            return

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        dlg = wx.TextEntryDialog(self, "Enter name of new target:", "Add Target", "")

        if dlg.ShowModal() != wx.ID_OK:
            return

        target_name = dlg.GetValue()
        target_name = target_name.replace("\\", "\\\\").replace("'", "\\'")

        new_target = mysql.cursor()
        new_target.execute("INSERT INTO cc_targets SET target = '%s', notes = ''" % target_name)

        # refresh the targets list.
        self.on_retrieve_targets(None)

        dlg.Destroy()


    ####################################################################################################################
    def on_right_click_popup_append_hits (self, event):
        '''
        Right click event handler for popup append hits menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)

        self.top.hits.append_hits(selected["id"])


    ####################################################################################################################
    def on_right_click_popup_clear_tag (self, event):
        '''
        Right click event handler for popup clear tag menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)
        mysql    = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        dlg = wx.MessageDialog(self, "Erase the recorded data under: %s?\n" % selected["tag"], "Confirm", wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT)

        if dlg.ShowModal() == wx.ID_NO:
            return

        dlg.Destroy()

        cursor = self.top.main_frame.mysql.cursor()
        cursor.execute("DELETE FROM cc_hits WHERE tag_id = '%d'" % selected["id"])


    ####################################################################################################################
    def on_right_click_popup_expand_tag (self, event):
        '''
        Right click event handler for popup expand tag menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)
        mysql    = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        dlg = wx.MessageDialog(self, "Expand out the basic blocks under: %s?\n" % selected["tag"], "Confirm", wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT)

        if dlg.ShowModal() == wx.ID_NO:
            return

        dlg.Destroy()

        busy = wx.BusyInfo("Expanding tag ... please wait.")
        wx.Yield()

        cc = utils.code_coverage.code_coverage(mysql=mysql)
        cc.import_mysql(selected["target_id"], selected["id"])

        no_modules = []
        new_hits   = []

        for ea in cc.hits.keys():
            hit = cc.hits[ea][0]

            # we are expanding out all the basic blocks of the hit functions.
            if not hit.is_function:
                continue

            # if we don't have the module for this hit, continue to the next one.
            if not self.top.pida_modules.has_key(hit.module):
                if not no_modules.count(hit.module):
                    no_modules.append(hit.module)
                    self.top.err("Necessary module '%s' for part of tag expansion missing, ignoring." % hit.module)
                continue

            # rebase the module if necessary.
            self.top.pida_modules[hit.module].rebase(hit.base)

            # grab the appropriate PIDA function.
            function = self.top.pida_modules[hit.module].functions[hit.eip]

            for bb_ea in function.basic_blocks.keys():
                if not cc.hits.has_key(bb_ea):
                    ccs             = utils.code_coverage.__code_coverage_struct__()
                    ccs.eip         = bb_ea
                    ccs.tid         = 0
                    ccs.num         = cc.num
                    ccs.timestamp   = 0
                    ccs.module      = hit.module
                    ccs.base        = hit.base
                    ccs.is_function = 0

                    new_hits.append(ccs)

                    # increment the internal counter.
                    cc.num += 1

        # manually propagate the new hits into the code coverage data structure.
        for ccs in new_hits:
            if not cc.hits.has_key(ccs.eip):
                cc.hits[ccs.eip] = []

            cc.hits[ccs.eip].append(ccs)

        # clear the current database entries and upload the new ones.
        cc.clear_mysql(selected["target_id"], selected["id"])
        cc.export_mysql(selected["target_id"], selected["id"])

        self.top.msg("Tag expansion complete, added %d new entries." % len(new_hits))


    ####################################################################################################################
    def on_right_click_popup_delete_tag (self, event):
        '''
        Right click event handler for popup delete tag menu selection.
        '''

        if not self.selected:
            return

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        selected = self.GetPyData(self.selected)

        dlg = wx.MessageDialog(self, "Delete tag: %s?" % selected["tag"], "Confirm", wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT)

        if dlg.ShowModal() == wx.ID_YES:
            cursor = mysql.cursor()
            cursor.execute("DELETE FROM cc_hits WHERE tag_id = '%d'" % selected["id"])
            cursor.execute("DELETE FROM cc_tags where     id = '%d'" % selected["id"])

            # refresh the targets list.
            self.on_retrieve_targets(None)

        dlg.Destroy()


    ####################################################################################################################
    def on_right_click_popup_delete_target (self, event):
        '''
        Right click event handler for popup delete target menu selection.
        '''

        if not self.selected:
            return

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        selected = self.GetPyData(self.selected)

        dlg = wx.MessageDialog(self, "Delete target: %s?" % selected["target"], "Confirm", wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT)
        if dlg.ShowModal() == wx.ID_YES:
            cursor = mysql.cursor()
            cursor.execute("DELETE FROM cc_targets WHERE id     = '%d'" % selected["id"])
            cursor.execute("DELETE FROM cc_hits WHERE target_id = '%d'" % selected["id"])
            cursor.execute("DELETE FROM cc_tags WHERE target_id = '%d'" % selected["id"])

            # refresh the targets list.
            self.on_retrieve_targets(None)

        dlg.Destroy()


    ####################################################################################################################
    def on_right_click_popup_load_hits (self, event):
        '''
        Right click event handler for popup load hits menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)

        self.top.hits.load_hits(selected["id"])


    ####################################################################################################################
    def on_right_click_popup_load_hits_all (self, event):
        '''
        Right click event handler for popup load all hits menu selection.
        '''

        if not self.selected:
            return

        (child, cookie) = self.GetFirstChild(self.selected)
        first_child     = child

        while child:
            data = self.GetPyData(child)

            if child == first_child:
                self.top.hits.load_hits(data["id"])
            else:
                self.top.hits.append_hits(data["id"])

            (child, cookie) = self.GetNextChild(child, cookie)


    ####################################################################################################################
    def on_right_click_popup_export_idc (self, event):
        '''
        Right click event handler for popup export IDA Python menu selection.
        '''

        if not self.selected:
            return

        data = self.GetPyData(self.selected)

        dlg = export_idc_dialog.export_idc_dialog(parent=self, top=self.top, tag_id=data["id"], target_id=data["target_id"])
        dlg.ShowModal()


    ####################################################################################################################
    def on_right_click_popup_filter_tag (self, event):
        '''
        Right click event handler for popup filter tag menu selection.
        '''

        if not self.selected:
            return

        # if the current item being marked for filtering, was the previous stalk ... clear it.
        if self.selected == self.used_for_stalk:
            self.used_for_stalk = None

        data             = self.GetPyData(self.selected)
        data["filtered"] = True

        self.SetPyData(self.selected, data)

        # set the icon for the selected item for filter.
        self.SetItemImage(self.selected, self.icon_filtered, wx.TreeItemIcon_Normal)

        # add the target / tag id pair to the top level filtered list.
        pair = (data["target_id"], data["id"])

        if not self.top.filter_list.count(pair):
            self.top.filter_list.append(pair)


    ####################################################################################################################
    def on_right_click_popup_properties (self, event):
        '''
        Right click event handler for popup export IDA Python menu selection.
        '''

        if not self.selected:
            return

        data = self.GetPyData(self.selected)

        dlg = target_properties.target_properties(parent=self, top=self.top, tag_id=data["id"], target_id=data["target_id"])
        dlg.ShowModal()


    ####################################################################################################################
    def on_right_click_popup_unfilter_tag (self, event):
        '''
        Right click event handler for popup unfilter tag menu selection.
        '''

        if not self.selected:
            return

        data = self.GetPyData(self.selected)
        del(data["filtered"])

        self.SetPyData(self.selected, data)

        # set the icon for the selected item for normal.
        self.SetItemImage(self.selected, self.icon_tag, wx.TreeItemIcon_Normal)

        # remove the target / tag id pair from the top level filtered list.
        self.top.filter_list.remove((data["target_id"], data["id"]))


    ####################################################################################################################
    def on_right_click_popup_use_for_stalk (self, event):
        '''
        Right click event handler for popup use for stalk menu selection.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)
        mysql    = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        # ensure the selected tag doesn't already contain data.
        cursor = mysql.cursor()
        cursor.execute("SELECT COUNT(tag_id) AS count FROM cc_hits WHERE tag_id = '%d'" % selected["id"])
        hit_count = cursor.fetchall()[0][0]

        # if it does, ensure the user wants to overwrite the existing data.
        if hit_count != 0:
            dlg = wx.MessageDialog(self, "Selected tag already contains %d hits, overwrite?" % hit_count, "Confirm", wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT)

            if dlg.ShowModal() == wx.ID_YES:
                cursor = mysql.cursor()
                cursor.execute("DELETE FROM cc_hits WHERE tag_id = '%d'" % selected["id"])
                dlg.Destroy()
            else:
                dlg.Destroy()
                return

        # clear the icon from the last item selected for stalking.
        if self.used_for_stalk:
            self.SetItemImage(self.used_for_stalk, self.icon_tag, wx.TreeItemIcon_Normal)

        # set the icon for the selected item for stalking.
        self.SetItemImage(self.selected, self.icon_selected, wx.TreeItemIcon_Normal)
        self.used_for_stalk = self.selected

        # grab the data structure for the selected item.
        data = self.GetPyData(self.selected)

        self.top.stalk_tag = data
        self.top.msg("Using '%s' as stalking tag." % data["tag"])


    ####################################################################################################################
    def on_right_click_popup_sync_udraw (self, event):
        '''
        Right click event handler for popup synchronize with uDraw menu selection.
        '''

        if not self.selected:
            return

        selected   = self.GetPyData(self.selected)
        self.udraw = self.top.main_frame.udraw
        mysql      = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        if not self.udraw:
            self.top.err("No available connection to uDraw(Graph) server.")
            return

        self.udraw.set_command_handler("node_double_click",      self.on_udraw_node_double_click)
        self.udraw.set_command_handler("node_selections_labels", self.on_udraw_node_selections_labels)

        self.cc = utils.code_coverage.code_coverage(mysql=mysql)
        self.cc.import_mysql(selected["target_id"], selected["id"])

        self.udraw_last_color     = None
        self.udraw_last_color_id  = None
        self.udraw_last_selected  = None
        self.udraw_base_graph     = None
        self.udraw_current_graph  = None
        self.udraw_hit_funcs      = []
        self.udraw_in_function    = False
        no_modules                = []

        for hit_list in self.cc.hits.values():
            hit = hit_list[0]

            # we can't graph what we don't have a module loaded for.
            if not self.top.pida_modules.has_key(hit.module):
                if not no_modules.count(hit.module):
                    no_modules.append(hit.module)
                    self.top.err("Necessary module '%s' to build part of graph missing, ignoring." % hit.module)
                continue

            # rebase the module if necessary.
            if hit.base and hit.base != self.top.pida_modules[hit.module].base:
                self.top.msg("Rebasing %s..." % hit.module)
                self.top.pida_modules[hit.module].rebase(hit.base)
                self.top.msg("Done. Rebased to %08x" % self.top.pida_modules[hit.module].base)

            # initially we are only going to graph the hit functions. so determine the function containing the hit.
            function = self.top.pida_modules[hit.module].find_function(hit.eip)

            if not function:
                self.top.err("Function containing %08x not found?!?" % hit.eip)
                continue

            # don't need to count functions more then once.
            if self.udraw_hit_funcs.count(function.ea_start):
                continue

            self.udraw_hit_funcs.append(function.ea_start)

            if not self.udraw_base_graph:
                self.udraw_base_graph = self.top.pida_modules[hit.module].graph_proximity(function.ea_start, 1, 1)
            else:
                tmp = self.top.pida_modules[hit.module].graph_proximity(function.ea_start, 1, 1)
                self.udraw_base_graph.graph_cat(tmp)

            # highlight the hit functions.
            self.udraw_base_graph.nodes[function.ea_start].color = 0xFF8000

        # if there is no graph to display, return.
        if not self.udraw_base_graph:
            self.top.err("Generated graph contains nothing to display.")
            return

        # set the initial function proximity graph and the current graph and display it.
        self.udraw_current_graph = self.udraw_base_graph
        self.udraw.graph_new(self.udraw_current_graph)

        # thread out the udraw connector message loop.
        thread.start_new_thread(self.udraw.message_loop, (None, None))


    ####################################################################################################################
    def on_retrieve_targets (self, event):
        '''
        Connect to the specified MySQL database, retrieve the target/tag list and propogate our custom list control.
        '''

        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        # make a record of the currently selected item so that we can unfold back to it in the event that we are simply
        # refreshing the tree control.
        selected = self.GetSelection()
        restore  = None

        if selected:
            selected = self.GetPyData(selected)

        # clear out the tree.
        self.DeleteChildren(self.root)

        if self.top.filter_list or self.top.stalk_tag:
            self.top.msg("Resetting filter list and stalk tag.")
            self.top.filter_list = []
            self.top.stalk_tag   = None

        # step through the list of targets.
        targets = mysql.cursor(MySQLdb.cursors.DictCursor)
        targets.execute("SELECT id, target FROM cc_targets ORDER BY target ASC")

        for target in targets.fetchall():
            target_to_append = self.AppendItem(self.root, target["target"])

            # if a previous item was selected, and it matches the id of the target we are adding, then set this
            # entry as the restore item.
            if selected and selected.has_key("target") and selected["id"] == target["id"]:
                restore = target_to_append

            self.SetPyData(target_to_append, target)
            self.SetItemImage(target_to_append, self.icon_folder,      wx.TreeItemIcon_Normal)
            self.SetItemImage(target_to_append, self.icon_folder_open, wx.TreeItemIcon_Expanded)

            # step through the tags for this target.
            tags = mysql.cursor(MySQLdb.cursors.DictCursor)
            tags.execute("SELECT id, target_id, tag FROM cc_tags WHERE target_id = '%d' ORDER BY tag ASC" % target["id"])

            for tag in tags.fetchall():
                tag_to_append = self.AppendItem(target_to_append, tag["tag"])

                # if a previous item was selected, and it matches the id of the tag we are adding, then set this entry
                # as the restore item.
                if selected and selected.has_key("tag") and selected["id"] == tag["id"]:
                    restore = tag_to_append

                self.SetPyData(tag_to_append, tag)
                self.SetItemImage(tag_to_append, self.icon_tag, wx.TreeItemIcon_Normal)

        # expand the tree.
        self.Expand(self.root)

        # if there was a previously selected item and it was found in the refreshed list, select it.
        if restore:
            self.SelectItem(restore)


    ####################################################################################################################
    def on_target_activated (self, event):
        '''
        Make record of the selected target/tag combination.
        '''

        if not self.selected:
            return

        selected = self.GetPyData(self.selected)

        # root node.
        if selected == None:
            pass

        # target node.
        elif selected.has_key("target"):
            pass

        # tag node.
        elif selected.has_key("tag"):
            pass


    ####################################################################################################################
    def on_target_right_click (self, event):
        if not self.selected:
            return

        # there's some weird case where if you click fast enough .x/.y don't exist. this catches that.
        try:
            if not self.x or not self.y:
                raise Exception
        except:
            return

        selected = self.GetPyData(self.selected)

        # root node.
        if selected == None:
            # we only have to do this once, that is what the hasattr() check is for.
            if not hasattr(self, "right_click_popup_add_target"):
                self.right_click_popup_add_target = wx.NewId()
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_add_target, id=self.right_click_popup_add_target)

            # make a menu.
            menu = wx.Menu()
            menu.Append(self.right_click_popup_add_target, "Add Target")

            self.PopupMenu(menu, (self.x, self.y))
            menu.Destroy()

        # target node.
        elif selected.has_key("target"):
            # we only have to do this once, that is what the hasattr() check is for.
            if not hasattr(self, "right_click_popup_add_tag"):
                self.right_click_popup_add_tag       = wx.NewId()
                self.right_click_popup_delete_target = wx.NewId()
                self.right_click_popup_load_hits_all = wx.NewId()

                self.Bind(wx.EVT_MENU, self.on_right_click_popup_add_tag,       id=self.right_click_popup_add_tag)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_delete_target, id=self.right_click_popup_delete_target)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_load_hits_all, id=self.right_click_popup_load_hits_all)

            # make a menu.
            menu = wx.Menu()
            menu.Append(self.right_click_popup_add_tag, "Add Tag")
            menu.AppendSeparator()
            menu.Append(self.right_click_popup_load_hits_all, "Load All Hits")
            menu.AppendSeparator()
            menu.Append(self.right_click_popup_delete_target, "Delete Target")

            self.PopupMenu(menu, (self.x, self.y))
            menu.Destroy()

        # tag node.
        elif selected.has_key("tag"):
            # we only have to do this once, that is what the hasattr() check is for.
            if not hasattr(self, "right_click_popup_load_hits"):
                self.right_click_popup_load_hits     = wx.NewId()
                self.right_click_popup_append_hits   = wx.NewId()
                self.right_click_popup_export_idc    = wx.NewId()
                self.right_click_popup_sync_udraw    = wx.NewId()
                self.right_click_popup_use_for_stalk = wx.NewId()
                self.right_click_popup_filter_tag    = wx.NewId()
                self.right_click_popup_unfilter_tag  = wx.NewId()
                self.right_click_popup_clear_tag     = wx.NewId()
                self.right_click_popup_expand_tag    = wx.NewId()
                self.right_click_popup_properties    = wx.NewId()
                self.right_click_popup_delete_tag    = wx.NewId()

                self.Bind(wx.EVT_MENU, self.on_right_click_popup_load_hits,     id=self.right_click_popup_load_hits)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_append_hits,   id=self.right_click_popup_append_hits)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_export_idc,    id=self.right_click_popup_export_idc)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_sync_udraw,    id=self.right_click_popup_sync_udraw)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_use_for_stalk, id=self.right_click_popup_use_for_stalk)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_filter_tag,    id=self.right_click_popup_filter_tag)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_unfilter_tag,  id=self.right_click_popup_unfilter_tag)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_clear_tag,     id=self.right_click_popup_clear_tag)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_expand_tag,    id=self.right_click_popup_expand_tag)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_properties,    id=self.right_click_popup_properties)
                self.Bind(wx.EVT_MENU, self.on_right_click_popup_delete_tag,    id=self.right_click_popup_delete_tag)

            # make a menu.
            menu = wx.Menu()
            menu.Append(self.right_click_popup_load_hits, "Load Hits")
            menu.Append(self.right_click_popup_append_hits, "Append Hits")
            menu.Append(self.right_click_popup_export_idc, "Export to IDA")
            menu.Append(self.right_click_popup_sync_udraw, "Sync with uDraw")
            menu.AppendSeparator()
            menu.Append(self.right_click_popup_use_for_stalk, "Use for Stalking")

            if selected.has_key("filtered"):
                menu.Append(self.right_click_popup_unfilter_tag, "Remove Tag Filter")
            else:
                menu.Append(self.right_click_popup_filter_tag, "Filter Tag")

            menu.Append(self.right_click_popup_clear_tag, "Clear Tag")
            menu.Append(self.right_click_popup_expand_tag, "Expand Tag")
            menu.Append(self.right_click_popup_properties, "Target/Tag Properties")
            menu.AppendSeparator()
            menu.Append(self.right_click_popup_delete_tag, "Delete Tag")

            self.PopupMenu(menu, (self.x, self.y))
            menu.Destroy()


    ####################################################################################################################
    def on_target_right_down (self, event):
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
    def on_target_sel_changed (self, event):
        '''
        Update the current selected tree control item on every selection change.
        '''

        self.selected = event.GetItem()


    ####################################################################################################################
    def on_udraw_node_selections_labels (self, udraw, args):
        '''
        uDraw callback handler for node selection.
        '''

        try:
            self.udraw_last_selected = args
            selected = long(self.udraw_last_selected[0], 16)
        except:
            return

        # update the focus in the hit list control.
        self.top.hits.focus_item_by_address(selected)

        # highlight the selected node in udraw.
        self.udraw_focus_node_by_address(selected)


    ####################################################################################################################
    def on_udraw_node_double_click (self, udraw, args):
        '''
        uDraw callback handler for node double click.
        '''

        selected = long(self.udraw_last_selected[0], 16)

        # if the activated node is a hit function, expand it.
        if selected in self.udraw_hit_funcs:
            self.udraw_change_view(selected, base=self.udraw_in_function)


    ####################################################################################################################
    def udraw_change_view (self, selected, base=False):
        '''
        Swap the current view with a function view / the calculated base graph.
        '''

        # back out to base graph.
        if base:
            self.udraw_current_graph = self.udraw_base_graph
            self.udraw_in_function   = False
            window_title             = ""

        # drill down into a function
        else:
            self.udraw_current_graph = self.udraw_base_graph.nodes[selected]
            self.udraw_in_function   = True
            window_title             = self.udraw_base_graph.nodes[selected].name

            # highlight the hit basic blocks within the function.
            for hit_list in self.cc.hits.values():
                hit = hit_list[0]

                if self.udraw_current_graph.nodes.has_key(hit.eip):
                    self.udraw_current_graph.nodes[hit.eip].color = 0xFF8000

        # render the new graph.
        self.udraw.graph_new(self.udraw_current_graph)
        self.udraw.window_title(window_title)
        self.udraw_focus_node_by_address(selected)


    ####################################################################################################################
    def udraw_focus_node_by_address (self, address):
        '''
        Focus and highlight the requested node. Restore the original color of any previously focused node.

        @type  address: DWORD
        @param address: Address of node to focus and highlight
        '''

        # if there is no connection to udraw, return.
        if not self.udraw_current_graph or not self.udraw:
            return

        # restore the last highlighted nodes color.
        if self.udraw_last_color:
            try:
                self.udraw.change_element_color("node", self.udraw_last_color_id, self.udraw_last_color)
                self.udraw_last_color = self.udraw_last_color_id = None
            except:
                self.top.err("Connection to uDraw severed.")
                self.udraw = None
                return

        # if the current view doesn't have the requested address.
        if not self.udraw_current_graph.nodes.has_key(address):
            # determine if it belongs to one of the hit functions.
            containing_function = None

            for hit_func in self.udraw_hit_funcs:
                if address in self.udraw_base_graph.nodes[hit_func].nodes.keys():
                    containing_function = hit_func

            # if the address could not be found in any of the hit functions, then return.
            if not containing_function:
                self.top.err("Could not locate containing function for %08x" % address)
                return

            # switch to function view.
            if containing_function == address:
                self.udraw_change_view(containing_function, base=True)
            else:
                self.udraw_change_view(containing_function, base=False)

        try:
            # save the color and id for restoring in the next iteration.
            self.udraw_last_color     = self.udraw_current_graph.nodes[address].color
            self.udraw_last_color_id  = address

            # focus and highlight the requested node.
            self.udraw.focus_node(address)
            self.udraw.change_element_color("node", address, 0x0080FF)
        except:
            self.top.err("Unable to locate %08x" % address)