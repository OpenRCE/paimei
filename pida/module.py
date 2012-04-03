#
# PIDA Module
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: module.py 235 2009-10-17 16:18:11Z pedram.amini $
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

try:
    from idaapi   import *
    from idautils import *
    from idc      import *
except:
    pass

import sys
import pgraph

from function import *
from defines  import *

class module (pgraph.graph):
    '''
    '''

    name      = None
    base      = None
    depth     = None
    analysis  = None
    signature = None
    ext       = {}

    ####################################################################################################################
    def __init__ (self, name="", signature=None, depth=DEPTH_FULL, analysis=ANALYSIS_NONE):
        '''
        Analysis of an IDA database requires the instantiation of this class and will handle, depending on the requested
        depth, the analysis of all functions, basic blocks, instructions and more specifically which analysis techniques
        to apply. For the full list of ananylsis options see defines.py. Specifying ANALYSIS_IMPORTS will require an
        extra one-time scan through the entire structure to propogate functions (nodes) and cross references (edges) for
        each reference API call. Specifying ANALYSIS_RPC will require an extra one-time scan through the entire IDA
        database and will propogate additional function level attributes.

        The signature attribute was added for use in the PaiMei process stalker module, for ensuring that a loaded
        DLL is equivalent to the PIDA file with matching name. Setting breakpoints in a non-matching module is
        obviously no good.

        @see: defines.py

        @type  name:      String
        @param name:      (Optional) Module name
        @type  signature: String
        @param signature: (Optional) Unique file signature to associate with module
        @type  depth:     Integer
        @param depth:     (Optional, Def=DEPTH_FULL) How deep to analyze the module
        @type  analysis:  Integer
        @param analysis:  (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        '''

        # run the parent classes initialization routine first.
        super(module, self).__init__(name)

        self.name      = name
        self.base      = MinEA() - 0x1000      # XXX - cheap hack
        self.depth     = depth
        self.analysis  = analysis
        self.signature = signature
        self.ext       = {}
        self.log       = True

        # convenience alias.
        self.functions = self.nodes

        # enumerate and add the functions within the module.
        if self.log:
            print "Analyzing functions..."

        for ea in Functions(MinEA(), MaxEA()):
            func = function(ea, self.depth, self.analysis, self)
            func.shape = "ellipse"
            self.add_node(func)

        # enumerate and add nodes for each import within the module.
        if self.depth & DEPTH_INSTRUCTIONS and self.analysis & ANALYSIS_IMPORTS:
            if self.log:
                print"Enumerating imports..."

            self.__init_enumerate_imports__()

        # enumerate and propogate attributes for any discovered RPC interfaces.
        if self.analysis & ANALYSIS_RPC:
            if self.log:
                print "Enumerating RPC interfaces..."

            self.__init_enumerate_rpc__()

        # enumerate and add the intramodular cross references.
        if self.log:
            print "Enumerating intramodular cross references..."

        for func in self.nodes.values():
            xrefs = list(CodeRefsTo(func.ea_start, 0))
            xrefs.extend(list(DataRefsTo(func.ea_start)))

            for ref in xrefs:
                from_func = get_func(ref)

                if from_func:
                    # GHETTO - add the actual source EA to the function.
                    if not self.nodes[from_func.startEA].outbound_eas.has_key(ref):
                        self.nodes[from_func.startEA].outbound_eas[ref] = []

                    self.nodes[from_func.startEA].outbound_eas[ref].append(func.ea_start)

                    edge = pgraph.edge(from_func.startEA, func.ea_start)

                    self.add_edge(edge)


    ####################################################################################################################
    def __init_enumerate_imports__ (self):
        '''
        Enumerate and add nodes / edges for each import within the module. This routine will pass through the entire
        module structure.
        '''

        for func in self.nodes.values():
            for bb in func.nodes.values():
                for instruction in bb.instructions.values():
                    if instruction.refs_api:
                        (address, api) = instruction.refs_api

                        node = function(address, module=self)
                        node.color = 0xB4B4DA
                        self.add_node(node)

                        edge = pgraph.edge(func.ea_start, address)
                        self.add_edge(edge)


    ####################################################################################################################
    def __init_enumerate_rpc__ (self):
        '''
        Enumerate all RPC interfaces and add additional properties to the RPC functions. This routine will pass through
        the entire IDA database. This was entirely ripped from my RPC enumeration IDC script::

            http://www.openrce.org/downloads/details/3/RPC%20Enumerator

        The approach appears to be stable enough.
        '''

        # walk through the entire database.
        # we don't just look at .text as .rdata also been spotted to house RPC structs.
        for loop_ea in Heads(MinEA(), MaxEA()):
            ea     = loop_ea;
            length = Byte(ea);
            magic  = Dword(ea + 0x18);

            # RPC_SERVER_INTERFACE found.
            if length == 0x44 and magic == 0x8A885D04:
                # grab the rpc interface uuid.
                uuid = ""
                for x in xrange(ea+4, ea+4+16):
                    uuid += chr(Byte(x))

                # jump to MIDL_SERVER_INFO.
                ea = Dword(ea + 0x3C);

                # jump to DispatchTable.
                ea = Dword(ea + 0x4);

                # enumerate the dispatch routines.
                opcode = 0
                while 1:
                    addr = Dword(ea)

                    if addr == BADADDR:
                        break

                    # sometimes ida doesn't correctly get the function start thanks to the whole 'mov reg, reg' noop
                    # nonsense. so try the next instruction.
                    if not len(GetFunctionName(addr)):
                        addr = NextNotTail(addr)

                    if not len(GetFunctionName(addr)):
                        break

                    if self.nodes.has_key(addr):
                        self.nodes[addr].rpc_uuid   = self.uuid_bin_to_string(uuid)
                        self.nodes[addr].rpc_opcode = opcode
                    else:
                        print "PIDA.MODULE> No function node for RPC routine @%08X" % addr

                    ea     += 4
                    opcode += 1


    ####################################################################################################################
    def find_function (self, ea):
        '''
        Locate and return the function that contains the specified address.

        @type  ea: DWORD
        @param ea: An address within the function to find

        @rtype:  pida.function
        @return: The function that contains the given address or None if not found.
        '''

        for func in self.nodes.values():
            # this check is necessary when analysis_depth == DEPTH_FUNCTIONS
            if func.ea_start == ea:
                return func

            for bb in func.nodes.values():
                if bb.ea_start <= ea <= bb.ea_end:
                    return func

        return None


    ####################################################################################################################
    def next_ea (self, ea=None):
        '''
        Return the instruction after to the one at ea. You can call this routine without an argument after the first
        call. The overall structure of PIDA was not really designed for this kind of functionality, so this is kind of
        a hack.

        @todo: See if I can do this better.

        @type  ea: (Optional, def=Last EA) Dword
        @param ea: Address of instruction to return next instruction from or -1 if not found.
        '''

        if not ea and self.current_ea:
            ea = self.current_ea

        function = self.find_function(ea)

        if not function:
            return -1

        ea_list = []

        for bb in function.nodes.values():
            ea_list.extend(bb.instructions.keys())

        ea_list.sort()

        try:
            idx = ea_list.index(ea)

            if idx == len(ea_list) - 1:
                raise Exception
        except:
            return -1

        self.current_ea = ea_list[idx + 1]
        return self.current_ea


    ####################################################################################################################
    def prev_ea (self, ea=None):
        '''
        Within the function that contains ea, return the instruction prior to the one at ea. You can call this routine
        without an argument after the first call. The overall structure of PIDA was not really designed for this kind of
        functionality, so this is kind of a hack.

        @todo: See if I can do this better.

        @type  ea: (Optional, def=Last EA) Dword
        @param ea: Address of instruction to return previous instruction to or None if not found.
        '''

        if not ea and self.current_ea:
            ea = self.current_ea

        function = self.find_function(ea)

        if not function:
            return -1

        ea_list = []

        for bb in function.nodes.values():
            ea_list.extend(bb.instructions.keys())

        ea_list.sort()

        try:
            idx = ea_list.index(ea)

            if idx == 0:
                raise Exception
        except:
            return -1

        self.current_ea = ea_list[idx - 1]
        return self.current_ea


    ####################################################################################################################
    def rebase (self, new_base):
        '''
        Rebase the module and all components with the new base address. This routine will check if the current and
        requested base addresses are equivalent, so you do not have to worry about checking that yourself.

        @type  new_base: Dword
        @param new_base: Address to rebase module to
        '''

        # nothing to do.
        if new_base == self.base:
            return

        # rebase each function in the module.
        for function in self.nodes.keys():
            self.nodes[function].id       = self.nodes[function].id       - self.base + new_base
            self.nodes[function].ea_start = self.nodes[function].ea_start - self.base + new_base
            self.nodes[function].ea_end   = self.nodes[function].ea_end   - self.base + new_base

            function = self.nodes[function]

            # rebase each basic block in the function.
            for bb in function.nodes.keys():
                function.nodes[bb].id       = function.nodes[bb].id       - self.base + new_base
                function.nodes[bb].ea_start = function.nodes[bb].ea_start - self.base + new_base
                function.nodes[bb].ea_end   = function.nodes[bb].ea_end   - self.base + new_base

                bb = function.nodes[bb]

                # rebase each instruction in the basic block.
                for ins in bb.instructions.keys():
                    bb.instructions[ins].ea = bb.instructions[ins].ea - self.base + new_base

                # fixup the instructions dictionary.
                old_dictionary  = bb.instructions
                bb.instructions = {}

                for key, val in old_dictionary.items():
                    bb.instructions[key - self.base + new_base] = val

            # fixup the functions dictionary.
            old_dictionary = function.nodes
            function.nodes = {}

            for key, val in old_dictionary.items():
                function.nodes[val.id] = val

            # rebase each edge between the basic blocks in the function.
            for edge in function.edges.keys():
                function.edges[edge].src =  function.edges[edge].src - self.base + new_base
                function.edges[edge].dst =  function.edges[edge].dst - self.base + new_base
                function.edges[edge].id  = (function.edges[edge].src << 32) + function.edges[edge].dst

            # fixup the edges dictionary.
            old_dictionary = function.edges
            function.edges = {}

            for key, val in old_dictionary.items():
                function.edges[val.id] = val

        # fixup the modules dictionary.
        old_dictionary = self.nodes
        self.nodes     = {}

        for key, val in old_dictionary.items():
            self.nodes[val.id] = val

        # rebase each edge between the functions in the module.
        for edge in self.edges.keys():
            self.edges[edge].src =  self.edges[edge].src - self.base + new_base
            self.edges[edge].dst =  self.edges[edge].dst - self.base + new_base
            self.edges[edge].id  = (self.edges[edge].src << 32) + self.edges[edge].dst

        # finally update the base address of the module.
        self.base = new_base


    ####################################################################################################################
    def uuid_bin_to_string (self, uuid):
        '''
        Convert the binary representation of a UUID to a human readable string.

        @type  uuid: Raw
        @param uuid: Raw binary bytes consisting of the UUID

        @rtype:  String
        @return: Human readable string representation of UUID.
        '''

        import struct

        (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
        (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

        return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)