#
# Process Stalker
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: process_stalker.py 194 2007-04-05 15:31:53Z cameron $
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

import thread
import sys

sys.path.append("..")

import code_coverage
import crash_binning
import pida

from pydbg import *
from pydbg.defines import *

# wx is not required for this module.
try:    import wx
except: pass

class process_stalker:
    '''
    This class was created to provide portable and re-usable Process Stalker functionality. Currently it is only being
    used by the pstalker PAIMEIconsole module.

    @todo: This utility has really only been used in the pstalker PAIMEIconsole module, it needs to be tested to ensure
           that it can be utilized standalone.
    '''

    FUNCTIONS    = 0
    BASIC_BLOCKS = 1

    attach              = 0
    load                = None
    args                = None
    cc                  = code_coverage.code_coverage()
    depth               = None
    detach              = False
    filter_list         = []
    filtered            = {}
    heavy               = False
    ignore_first_chance = True
    log                 = lambda x: None
    main                = None
    mysql               = None
    pida_modules        = None
    pydbg               = None
    restore             = False
    tag_id              = None
    target_id           = None

    ####################################################################################################################
    def __init__ (self, depth, filter_list, log, main, mysql, pida_modules, pydbg, tag_id, target_id, print_bps=True, \
                        attach=0, load=None, args=None, heavy=False, ignore_first_chance=True, restore=False):
        '''
        Initialize the process stalker object, not all arguments are required.

        @type  depth:               Integer (self.FUNCTIONS=0 or self.BASIC_BLOCKS=1)
        @param depth:               0 for function level stalking, 1 for basic block level stalking
        @type  filter_list:         List
        @param filter_list:         List of (target id, tag id) tuples to filter from stalking
        @type  log:                 Function Pointer
        @param log:                 Pointer to log routine that takes a single parameter, the log message
        @type  main:                String
        @param main:                Name of the main module
        @type  mysql:               MySQLdb Connection
        @param mysql:               Connection to MySQL server
        @type  pida_modules:        Dictionary
        @param pida_modules:        Dictionary of loaded PIDA modules, keyed by module name
        @type  pydbg:               PyDbg
        @param pydbg:               PyDbg instance
        @type  tag_id:              Integer
        @param tag_id:              ID of tag we are storing hits in
        @type  target_id:           Integer
        @param target_id:           ID ot target that contains the tag we are storing hits in
        @type  print_bps:           Boolean
        @param print_bps:           (Optional, def=False) Controls whether or not to log individual breakpoint hits
        @type  attach:              Integer
        @param attach:              (Optional, def=0) Process ID of target to attach to
        @type  load:                String
        @param load:                (Optional, def=None) Command line to executable when loading target
        @type  args:                String
        @param args:                (Optional, def=None) Optional command line arguments to use when loading target
        @type  heavy:               Boolean
        @param heavy:               (Optional, def=False) Controls whether or not context data is recorded
        @type  ignore_first_chance: Boolean
        @param ignore_first_chance: (Optional, def=True) Controls reporting of first chance exceptions
        @type  restore:             Boolean
        @param restore:             (Optional, def=False) Controls whether or not to restore hit breakpoints
        '''

        self.attach              = attach
        self.load                = load
        self.args                = args
        self.cc                  = code_coverage.code_coverage()
        self.depth               = depth
        self.filter_list         = filter_list
        self.filtered            = {}
        self.heavy               = heavy
        self.ignore_first_chance = ignore_first_chance
        self.log                 = log
        self.main                = main
        self.mysql               = mysql
        self.pida_modules        = pida_modules
        self.pydbg               = pydbg
        self.print_bps           = print_bps
        self.restore             = restore
        self.tag_id              = tag_id
        self.target_id           = target_id


    ####################################################################################################################
    def export_mysql (self):
        '''
        Export all the recorded hits to the database.
        '''

        if self.cc.num > 1:
            self.log("Exporting %d hits to MySQL." % (self.cc.num - 1))
            self.cc.mysql = self.mysql
            self.cc.export_mysql(self.target_id, self.tag_id)
            self.cc.reset()


    ####################################################################################################################
    def handler_access_violation (self, dbg):
        '''
        If the shit hits the fan, we want to know about it.
        '''

        # if the user wants to ignore first chance exceptions then do so.
        if self.ignore_first_chance and dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED

        crash_bin = crash_binning.crash_binning()
        crash_bin.record_crash(dbg)

        self.log(crash_bin.crash_synopsis())
        dbg.terminate_process()
        self.export_mysql()


    ####################################################################################################################
    def handler_breakpoint (self, dbg):
        '''
        The breakpoint handler is of course responsible for logging the code coverage.
        '''

        if dbg.get_attr("first_breakpoint"):
            return DBG_CONTINUE

        if self.print_bps:
            self.log("debugger hit %08x cc #%d" % (dbg.exception_address, self.cc.num))

        is_function = 0
        for module in self.pida_modules.values():
            if module.nodes.has_key(dbg.context.Eip):
                is_function = 1
                break

        self.cc.add(dbg, is_function)

        return DBG_CONTINUE


    ####################################################################################################################
    def handler_load_dll (self, dbg):
        '''
        Generate debug messages on DLL loads and keep track of the last loaded DLL.
        '''

        last_dll = dbg.get_system_dll(-1)
        self.log("Loading 0x%08x %s" % (last_dll.base, last_dll.path))

        self.set_bps(last_dll.name.lower(), last_dll)

        return DBG_CONTINUE


    ####################################################################################################################
    def handler_user_callback (self, dbg):
        '''
        This is my elegant solution to avoiding having to thread out the stalk routine.
        '''

        # wx is not required for this module.
        try:    wx.Yield()
        except: pass

        if self.detach:
            # reset the flag and push data to mysql before we try to detach, in case detaching fails.
            self.detach = False

            self.export_mysql()
            dbg.detach()


    ####################################################################################################################
    def set_bps (self, module, last_dll=None):
        '''
        Set breakpoints in the specified module.

        @type  module:   String
        @param module:   Name of module (exe or dll) to set breakpoints in
        @type  last_dll: PyDbg System DLL Object
        @param last_dll: (Optional, def=None) System DLL instance, required for setting breakpoints in a DLL.
        '''

        if module in self.pida_modules.keys():
            # if we are setting breakpoints in a DLL.
            if last_dll:
                # if a signature is available, ensure we have a match before we start setting breakpoints in the loaded DLL.
                if self.pida_modules[module].signature:
                    if self.pida_modules[module].signature != pida.signature(last_dll.path):
                        self.log("Signature match failed, ignoring DLL")
                        return

                # ensure the pida module is at the appropriate base address.
                self.pida_modules[module].rebase(last_dll.base)

            # otherwise we are setting breakpoints in the main module. determine the base address of the main module
            # and rebase if necessary.
            else:
                for mod32 in self.pydbg.iterate_modules():
                    if mod32.szModule.lower() == module.lower():
                        self.pida_modules[module].rebase(mod32.modBaseAddr)

            #
            # function level tracking.
            #

            if self.depth == self.FUNCTIONS:
                functions = []

                for f in self.pida_modules[module].nodes.values():
                    if f.is_import:
                        continue

                    if self.filtered.has_key(module):
                        if self.filtered[module].count(f.ea_start - self.pida_modules[module].base):
                            continue

                    functions.append(f.ea_start)

                if last_dll: self.log("Setting %d breakpoints on functions in %s" % (len(functions), last_dll.name))
                else:        self.log("Setting %d breakpoints on functions in main module" % len(functions))

                self.pydbg.bp_set(functions, restore=self.restore)

            #
            # basic block level tracking.
            #

            elif self.depth == self.BASIC_BLOCKS:
                basic_blocks = []

                for f in self.pida_modules[module].nodes.values():
                    for bb in f.nodes.values():
                        if self.filtered.has_key(module):
                            if self.filtered[module].count(bb.ea_start - self.pida_modules[module].base):
                                continue

                        basic_blocks.append(bb.ea_start)

                if last_dll: self.log("Setting %d breakpoints on basic blocks in %s" % (len(basic_blocks), last_dll.name))
                else:        self.log("Setting %d breakpoints on basic blocks in main module" % len(basic_blocks))

                self.pydbg.bp_set(basic_blocks, restore=self.restore)


    ####################################################################################################################
    def stalk (self):
        '''
        This is the main routine of the process stalker utility class. Once all the required member variables are set
        you call this routine to get the ball rolling and start stalking.

        @todo: Add sanity checking to ensure all required member variables are set.
        '''

        self.pydbg.set_callback(EXCEPTION_BREAKPOINT,       self.handler_breakpoint)
        self.pydbg.set_callback(LOAD_DLL_DEBUG_EVENT,       self.handler_load_dll)
        self.pydbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.handler_access_violation)
        self.pydbg.set_callback(USER_CALLBACK_DEBUG_EVENT,  self.handler_user_callback)

        # set the main module name for the code coverage class.
        self.cc.main_module = self.main

        # retrieve the entries to filter from the filter list.
        for (target_id, tag_id) in self.filter_list:
            cc = code_coverage.code_coverage()
            cc.mysql = self.mysql

            cc.import_mysql(target_id, tag_id)

            self.log("Filtering %d points from target id:%d tag id:%d" % (cc.num, target_id, tag_id))

            for hit_list in cc.hits.values():
                for hit in hit_list:
                    if not self.filtered.has_key(hit.module):
                        self.filtered[hit.module] = []

                    if not self.filtered[hit.module].count(hit.eip - hit.base):
                        self.filtered[hit.module].append(hit.eip - hit.base)

        self.cc.heavy = self.heavy

        try:
            if self.load:
                self.pydbg.load(self.load, self.args)
            else:
                self.pydbg.attach(self.attach)
        except pdx, x:
            self.log(x.__str__())
            return

        self.set_bps(self.main)

        try:
            self.pydbg.run()
        except pdx, x:
            self.log(x.__str__())

        self.export_mysql()