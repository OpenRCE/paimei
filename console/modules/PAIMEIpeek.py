#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PAIMEIpeek.py 194 2007-04-05 15:31:53Z cameron $
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
import sys
import MySQLdb
import time

import _PAIMEIpeek

from pydbg import *
from pydbg.defines import *

import utils

########################################################################################################################
class PAIMEIpeek(wx.Panel):
    '''
    The Process Peeker module panel.
    '''

    documented_properties = {
        "boron_tag"  : "Optional string to search context dumps for and alarm the user if found.",
        "log_file"   : "Optional filename to save a copy of all log output to.",
        "module"     : "MySQLdb object for currently selection module.",
        "quiet"      : "Boolean flag controlling whether or not to log context dumps during run-time.",
        "track_recv" : "Boolean flag controlling whether or not to capture and log recv() / recvfrom() data.",
        "watch"      : "Instead of attaching to or loading a target process, this option allows you to specify a process name to continuously watch for and attach to as soon as it is spawned. The process name is case insensitive, but you *must* specify the full name and extension. Example: winmine.exe",
    }

    boron_tag  = ""
    log_file   = ""
    module     = None
    quiet      = False
    track_recv = True
    watch      = None

    # attach target.
    pid    = proc = load = None
    detach = False

    def __init__(self, *args, **kwds):
        # begin wxGlade: PAIMEIpeek.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)

        self.log_splitter                  = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER)
        self.log_window                    = wx.Panel(self.log_splitter, -1)
        self.top_window                    = wx.Panel(self.log_splitter, -1)
        self.hit_list_column_staticbox     = wx.StaticBox(self.top_window, -1, "Hits")
        self.peek_data_container_staticbox = wx.StaticBox(self.top_window, -1, "Peek Point Data")
        self.recon_column_staticbox        = wx.StaticBox(self.top_window, -1, "RECON")
        self.select_module                 = wx.Button(self.top_window, -1, "Select Module")
        self.add_recon_point               = wx.Button(self.top_window, -1, "Add RECON Point")
        self.set_options                   = wx.Button(self.top_window, -1, "Options")
        self.attach_detach                 = wx.Button(self.top_window, -1, "Peek!")
        self.recon                         = _PAIMEIpeek.ReconListCtrl.ReconListCtrl(self.top_window, -1, style=wx.LC_REPORT|wx.LC_SINGLE_SEL|wx.LC_HRULES|wx.SUNKEN_BORDER, top=self)
        self.hit_list                      = wx.ListBox(self.top_window, -1, choices=[])
        self.peek_data                     = wx.TextCtrl(self.top_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)
        self.log                           = wx.TextCtrl(self.log_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)
        self.percent_analyzed_static       = wx.StaticText(self.top_window, -1, "RECON Points Reviewed:")
        self.percent_analyzed              = wx.Gauge(self.top_window, -1, 100, style=wx.GA_HORIZONTAL|wx.GA_SMOOTH)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        self.list_book  = kwds["parent"]             # handle to list book.
        self.main_frame = self.list_book.top         # handle to top most frame.

        # move the log splitter sash down.
        self.log_splitter.SetSashPosition(-200, redraw=True)

        # log window bindings.
        self.Bind(wx.EVT_TEXT_MAXLEN, self.on_log_max_length_reached, self.log)

        # hide the ID and depth columns (oh yeah, very ollydbg-ish).
        self.recon.SetColumnWidth(0, 0)
        self.recon.SetColumnWidth(2, 0)

        # button bindings
        self.Bind(wx.EVT_BUTTON, self.on_button_select_module,   self.select_module)
        self.Bind(wx.EVT_BUTTON, self.on_button_add_recon_point, self.add_recon_point)
        self.Bind(wx.EVT_BUTTON, self.on_button_set_options,     self.set_options)
        self.Bind(wx.EVT_BUTTON, self.on_button_attach_detach,   self.attach_detach)

        # list box bindings.
        self.Bind(wx.EVT_LISTBOX, self.on_hit_list_select, self.hit_list)

        # recon list control bindings.
        self.recon.Bind(wx.EVT_LIST_ITEM_SELECTED,  self.recon.on_select)
        self.recon.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.recon.on_right_click)
        self.recon.Bind(wx.EVT_RIGHT_UP,            self.recon.on_right_click)
        self.recon.Bind(wx.EVT_RIGHT_DOWN,          self.recon.on_right_down)
        self.recon.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.recon.on_activated)

        self.msg("PaiMei Peeker")
        self.msg("Module by Pedram Amini\n")


    ####################################################################################################################
    def __set_properties(self):
        # begin wxGlade: PAIMEIpeek.__set_properties
        self.select_module.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.add_recon_point.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.set_options.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.attach_detach.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.recon.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.peek_data.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.log.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))
        self.percent_analyzed_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.percent_analyzed.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        # end wxGlade


    ####################################################################################################################
    def __do_layout(self):
        # begin wxGlade: PAIMEIpeek.__do_layout
        overall = wx.BoxSizer(wx.VERTICAL)
        log_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        columns = wx.BoxSizer(wx.HORIZONTAL)
        peek_data_container = wx.StaticBoxSizer(self.peek_data_container_staticbox, wx.HORIZONTAL)
        hit_list_column = wx.StaticBoxSizer(self.hit_list_column_staticbox, wx.HORIZONTAL)
        recon_column = wx.StaticBoxSizer(self.recon_column_staticbox, wx.VERTICAL)
        button_row = wx.BoxSizer(wx.HORIZONTAL)
        button_row.Add(self.select_module, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_row.Add(self.add_recon_point, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_row.Add(self.set_options, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        button_row.Add(self.attach_detach, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        recon_column.Add(button_row, 0, wx.EXPAND, 0)
        recon_column.Add(self.recon, 1, wx.EXPAND, 0)
        recon_column.Add(self.percent_analyzed_static, 0, wx.EXPAND, 0)
        recon_column.Add(self.percent_analyzed, 0, wx.EXPAND, 0)
        columns.Add(recon_column, 1, wx.EXPAND, 0)
        hit_list_column.Add(self.hit_list, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        columns.Add(hit_list_column, 0, wx.EXPAND, 0)
        peek_data_container.Add(self.peek_data, 1, wx.EXPAND, 0)
        columns.Add(peek_data_container, 1, wx.EXPAND, 0)
        self.top_window.SetAutoLayout(True)
        self.top_window.SetSizer(columns)
        columns.Fit(self.top_window)
        columns.SetSizeHints(self.top_window)
        log_window_sizer.Add(self.log, 1, wx.EXPAND, 0)
        self.log_window.SetAutoLayout(True)
        self.log_window.SetSizer(log_window_sizer)
        log_window_sizer.Fit(self.log_window)
        log_window_sizer.SetSizeHints(self.log_window)
        self.log_splitter.SplitHorizontally(self.top_window, self.log_window)
        overall.Add(self.log_splitter, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        # end wxGlade


    ####################################################################################################################
    def err (self, message):
        '''
        Write an error message to log window.
        '''

        self.log.AppendText("[!] %s\n" % message)


    ####################################################################################################################
    def msg (self, message):
        '''
        Write a log message to log window.
        '''

        self.log.AppendText("[*] %s\n" % message)

        # if a log file was specified, write the message to it as well.
        if self.log_file:
            try:
                fh = open(self.log_file, "a+")
                fh.write(message + "\n")
                fh.close()
            except:
                self.err("Failed writing to log file '%s'. Closing log." % self.log_file)
                self.log_file = None


    ####################################################################################################################
    def handler_access_violation (self, dbg):
        '''
        '''

        crash_bin = utils.crash_binning()
        crash_bin.record_crash(dbg)

        self.msg(crash_bin.crash_synopsis())
        dbg.terminate_process()


    ####################################################################################################################
    def handler_breakpoint (self, dbg):
        '''
        On the first breakpoint set all the other breakpoints on the recon points. If track_recg is enabled then
        establish hooks on the winsock functions. On subsequent breakpoints, record them appropriately.
        '''

        #
        # first breakpoint, set hooks and breakpoints on recon points.
        #

        if dbg.first_breakpoint:
            if self.track_recv:
                self.hooks = utils.hook_container()

                # ESP                 +4         +8       +C        +10
                # int recv     (SOCKET s, char *buf, int len, int flags)
                # int recvfrom (SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
                # we want these:                ^^^      ^^^

                try:
                    ws2_recv = dbg.func_resolve("ws2_32",  "recv")
                    self.hooks.add(dbg, ws2_recv, 4, None, self.socket_logger_ws2_recv)
                except:
                    pass

                try:
                    ws2_recvfrom = dbg.func_resolve("ws2_32",  "recvfrom")
                    self.hooks.add(dbg, ws2_recvfrom, 4, None, self.socket_logger_ws2_recvfrom)
                except:
                    pass

                try:
                    wsock_recv = dbg.func_resolve("wsock32", "recv")
                    self.hooks.add(dbg, wsock_recv, 4, None, self.socket_logger_wsock_recv)
                except:
                    pass

                try:
                    wsock_recvfrom = dbg.func_resolve("wsock32", "recvfrom")
                    self.hooks.add(dbg, wsock_recvfrom, 4, None, self.socket_logger_wsock_recvfrom)
                except:
                    pass

            # retrieve list of recon points.
            cursor = self.main_frame.mysql.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT id, offset, stack_depth FROM pp_recon WHERE module_id = '%d'" % self.module["id"])

            # create a mapping of addresses to recon MySQL objects.
            self.addr_to_recon = {}
            for row in cursor.fetchall():
                self.addr_to_recon[self.module["base"] + row["offset"]] = row

            # set breakpoints at each recon point.
            self.dbg.bp_set(self.addr_to_recon.keys())
            self.msg("Watching %d points" % len(self.addr_to_recon))

            # close the MySQL cursor and continue execution.
            cursor.close()
            return DBG_CONTINUE

        #
        # subsequent breakpoints are recon hits ... export to db.
        #

        # grab the current context.
        context_dump = dbg.dump_context(stack_depth=self.addr_to_recon[dbg.context.Eip]["stack_depth"], print_dots=False)

        # display the context if the 'quiet' option is not enabled.
        if not self.quiet:
            self.msg(context_dump)

        # no boron tag match by default.
        boron_found = ""

        # if it was specified, search for the boron tag in the current context.
        if self.boron_tag:
            if context_dump.lower().find(self.boron_tag.lower()) != -1:
                boron_found = self.boron_tag

                # update the boron tag field of the pp_recon table to reflect that a hit was made.
                cursor = self.main_frame.mysql.cursor()
                cursor.execute("UPDATE pp_recon SET boron_tag='%s' WHERE id='%d'" % (boron_found, self.addr_to_recon[dbg.context.Eip]["id"]))
                cursor.close()

                if not self.quiet:
                    self.msg(">>>>>>>>>>>>>>>>>>>> BORON TAG FOUND IN ABOVE CONTEXT DUMP <<<<<<<<<<<<<<<<<<<<")


        # retrieve the context list with 'hex_dump' enabled to store in the database.
        context_list = dbg.dump_context_list(stack_depth=4, hex_dump=True)

        sql  = " INSERT INTO pp_hits"
        sql += " SET recon_id     = '%d'," % self.addr_to_recon[dbg.context.Eip]["id"]
        sql += "     module_id    = '%d'," % self.module["id"]
        sql += "     timestamp    = '%d'," % int(time.time())
        sql += "     tid          = '%d'," % dbg.dbg.dwThreadId
        sql += "     eax          = '%d'," % dbg.context.Eax
        sql += "     ebx          = '%d'," % dbg.context.Ebx
        sql += "     ecx          = '%d'," % dbg.context.Ecx
        sql += "     edx          = '%d'," % dbg.context.Edx
        sql += "     edi          = '%d'," % dbg.context.Edi
        sql += "     esi          = '%d'," % dbg.context.Esi
        sql += "     ebp          = '%d'," % dbg.context.Ebp
        sql += "     esp          = '%d'," % dbg.context.Esp
        sql += "     esp_4        = '%d'," % context_list["esp+04"]["value"]
        sql += "     esp_8        = '%d'," % context_list["esp+08"]["value"]
        sql += "     esp_c        = '%d'," % context_list["esp+0c"]["value"]
        sql += "     esp_10       = '%d'," % context_list["esp+10"]["value"]
        sql += "     eax_deref    = '%s'," % context_list["eax"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     ebx_deref    = '%s'," % context_list["ebx"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     ecx_deref    = '%s'," % context_list["ecx"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     edx_deref    = '%s'," % context_list["edx"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     edi_deref    = '%s'," % context_list["edi"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esi_deref    = '%s'," % context_list["esi"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     ebp_deref    = '%s'," % context_list["ebp"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esp_deref    = '%s'," % context_list["esp"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esp_4_deref  = '%s'," % context_list["esp+04"]["desc"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esp_8_deref  = '%s'," % context_list["esp+08"]["desc"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esp_c_deref  = '%s'," % context_list["esp+0c"]["desc"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     esp_10_deref = '%s'," % context_list["esp+10"]["desc"].replace("\\", "\\\\").replace("'", "\\'")
        sql += "     boron_tag    = '%s'," % boron_found
        sql += "     base         = '%d' " % self.module["base"]

        cursor = self.main_frame.mysql.cursor()
        cursor.execute(sql)
        cursor.close()

        return DBG_CONTINUE


    ####################################################################################################################
    def handler_user_callback (self, dbg):
        '''
        '''

        # we try/except this as sometimes there is a recursion error that we don't care about.
        try:    wx.Yield()
        except: pass

        if self.detach:
            self.detach = False
            self.dbg.detach()

    ####################################################################################################################
    def on_button_add_recon_point (self, event):
        # a console-wide username must be specified for this action.
        if not self.main_frame.username:
            self.err("You must tell PaiMei who you are to continue with this action.")
            return

        # can't do anything if a module isn't loaded.
        if not self.module:
            self.err("You must load a module first.")
            return

        dlg = _PAIMEIpeek.AddReconDlg.AddReconDlg(parent=self)
        dlg.ShowModal()


    ####################################################################################################################
    def on_button_attach_detach (self, event):
        '''
        Present a dialog box with process list / load controls and begin monitoring the selected target.
        '''

        #
        # if we are already peeking and this button was hit, then step peeking and return.
        #

        if self.attach_detach.GetLabel() == "Stop":
            self.detach = True
            self.attach_detach.SetLabel("Peek!")

            # refresh the list.
            self.recon.load(self.module["id"])
            return

        #
        # it's peeking time.
        #

        # can't do anything if a module isn't loaded.
        if not self.module:
            self.err("You must load a module first.")
            return

        dlg = _PAIMEIpeek.PyDbgDlg.PyDbgDlg(parent=self)

        if dlg.ShowModal() != wx.ID_CANCEL:
            # create a new debugger instance..
            if hasattr(self.main_frame.pydbg, "port"):
                self.dbg = pydbg_client(self.main_frame.pydbg.host, self.main_frame.pydbg.port)
            else:
                self.dbg = pydbg()

            self.dbg.set_callback(EXCEPTION_BREAKPOINT,       self.handler_breakpoint)
            self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.handler_access_violation)
            self.dbg.set_callback(USER_CALLBACK_DEBUG_EVENT,  self.handler_user_callback)

            if self.load:
                self.dbg.load(self.load)
            else:
                self.dbg.attach(self.pid)

            self.attach_detach.SetLabel("Stop")
            self.dbg.run()


    ####################################################################################################################
    def on_button_select_module (self, event):
        '''
        Utilize the MySQL connection to retrieve the list of available modules from pp_modules.
        '''

        mysql = self.main_frame.mysql

        if not mysql:
            self.err("No available connection to MySQL server.")
            return

        busy = wx.BusyInfo("Loading... please wait.")
        wx.Yield()

        # step through the hits for this tag id.
        hits = mysql.cursor(MySQLdb.cursors.DictCursor)
        hits.execute("SELECT id, name FROM pp_modules ORDER BY name ASC")

        choices = {}
        for hit in hits.fetchall():
            choices[hit["name"]] = hit["id"]

        dlg = wx.SingleChoiceDialog(self, "", "Select Module", choices.keys(), wx.CHOICEDLG_STYLE)

        if dlg.ShowModal() == wx.ID_OK:
            name = dlg.GetStringSelection()
            id   = choices[name]

            self.msg("Loading %s" % name)
            self.recon.load(id)

        dlg.Destroy()


    ####################################################################################################################
    def on_button_set_options (self, event):
        '''
        Instantiate a dialog that will bubble set options back into our class vars.
        '''

        dlg = _PAIMEIpeek.PeekOptionsDlg.PeekOptionsDlg(parent=self)
        dlg.ShowModal()


    ####################################################################################################################
    def on_hit_list_select (self, event, id=None):
        '''
        A line item in the hit list control was selected, load the details for the hit.
        '''

        if not id:
            hit_id = event.GetClientData()
        else:
            hit_id = id

        cursor = self.main_frame.mysql.cursor(MySQLdb.cursors.DictCursor)

        try:
            cursor.execute("SELECT * FROM pp_hits WHERE id = '%d'" % hit_id)
            hit = cursor.fetchone()
        except:
            self.err("MySQL query failed.")
            return

        separator = "-" * 72

        context_dump  = "ID: %04x\n" % hit["id"]

        if hit["boron_tag"]:
            context_dump += ">>>>>>>>>> BORON TAG HIT: %s\n" % hit["boron_tag"]

        context_dump += "\n"
        context_dump += "%s\nEAX: %08x (%10d)\n%s\n\n" % (separator, hit["eax"], hit["eax"], hit["eax_deref"])
        context_dump += "%s\nEBX: %08x (%10d)\n%s\n\n" % (separator, hit["ebx"], hit["ebx"], hit["ebx_deref"])
        context_dump += "%s\nECX: %08x (%10d)\n%s\n\n" % (separator, hit["ecx"], hit["ecx"], hit["ecx_deref"])
        context_dump += "%s\nEDX: %08x (%10d)\n%s\n\n" % (separator, hit["edx"], hit["edx"], hit["edx_deref"])
        context_dump += "%s\nEDI: %08x (%10d)\n%s\n\n" % (separator, hit["edi"], hit["edi"], hit["edi_deref"])
        context_dump += "%s\nESI: %08x (%10d)\n%s\n\n" % (separator, hit["esi"], hit["esi"], hit["esi_deref"])
        context_dump += "%s\nEBP: %08x (%10d)\n%s\n\n" % (separator, hit["ebp"], hit["ebp"], hit["ebp_deref"])
        context_dump += "%s\nESP: %08x (%10d)\n%s\n\n" % (separator, hit["esp"], hit["esp"], hit["esp_deref"])

        context_dump += "%s\nESP +04: %08x (%10d)\n%s\n\n" % (separator, hit["esp_4"],  hit["esp_4"],  hit["esp_4_deref"])
        context_dump += "%s\nESP +08: %08x (%10d)\n%s\n\n" % (separator, hit["esp_8"],  hit["esp_8"],  hit["esp_8_deref"])
        context_dump += "%s\nESP +0C: %08x (%10d)\n%s\n\n" % (separator, hit["esp_c"],  hit["esp_c"],  hit["esp_c_deref"])
        context_dump += "%s\nESP +10: %08x (%10d)\n%s\n\n" % (separator, hit["esp_10"], hit["esp_10"], hit["esp_10_deref"])

        self.peek_data.SetValue(context_dump)


    ####################################################################################################################
    def on_log_max_length_reached (self, event):
        '''
        Clear the log window when the max length is reach.

        @todo: Make this smarter by maybe only clearing half the lines.
        '''

        self.log.SetValue("")


    ####################################################################################################################
    def socket_logger_ws2_recv (self, dbg, args, ret):
        '''
        Hook container call back.
        '''

        self.msg("ws2_32.recv(buf=%08x, len=%d)" % (args[1], args[2]))
        self.msg("Actually received %d bytes:" % ret)
        self.msg(dbg.hex_dump(dbg.read(args[1], ret)))


    ####################################################################################################################
    def socket_logger_ws2_recvfrom (self, dbg, args, ret):
        '''
        Hook container call back.
        '''

        self.msg("ws2_32.recvfrom(buf=%08x, len=%d)" % (args[1], args[2]))
        self.msg("Actually received %d bytes:" % ret)
        self.msg(dbg.hex_dump(dbg.read(args[1], ret)))


    ####################################################################################################################
    def socket_logger_wsock_recv (self, dbg, args, ret):
        '''
        Hook container call back.
        '''

        self.msg("wsock32.recv(buf=%08x, len=%d)" % (args[1], args[2]))
        self.msg("Actually received %d bytes:" % ret)
        self.msg(dbg.hex_dump(dbg.read(args[1], ret)))


    ####################################################################################################################
    def socket_logger_wsock_recvfrom (self, dbg, args, ret):
        '''
        Hook container call back.
        '''

        self.msg("wsock32.recvfrom(buf=%08x, len=%d)" % (args[1], args[2]))
        self.msg("Actually received %d bytes:" % ret)
        self.msg(dbg.hex_dump(dbg.read(args[1], ret)))