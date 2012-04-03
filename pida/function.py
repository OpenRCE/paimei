#
# PIDA Function
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: function.py 251 2011-01-01 14:43:47Z my.name.is.sober $
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

import pgraph

from basic_block import *
from defines     import *

class function (pgraph.graph, pgraph.node):
    '''
    '''

    # GHETTO - we want to store the actual function to function edge start address.
    outbound_eas     = {}

    depth            = None
    analysis         = None
    module           = None
    num_instructions = 0

    id               = None
    ea_start         = None
    ea_end           = None
    name             = None
    is_import        = False
    flags            = None

    rpc_uuid         = None
    rpc_opcode       = None

    saved_reg_size   = 0
    frame_size       = 0
    ret_size         = 0

    local_vars       = {}
    local_var_size   = 0
    num_local_vars   = 0

    args             = {}
    arg_size         = 0
    num_args         = 0
    chunks           = []

    ext              = {}

    ####################################################################################################################
    def __init__ (self, ea_start, depth=DEPTH_FULL, analysis=ANALYSIS_NONE, module=None):
        '''
        Analyze all the function chunks associated with the function starting at ea_start.
        self.fill(ea_start).

        @see: defines.py

        @type  ea_start: DWORD
        @param ea_start: Effective address of start of function (inclusive)
        @type  depth:    Integer
        @param depth:    (Optional, Def=DEPTH_FULL) How deep to analyze the module
        @type  analysis: Integer
        @param analysis: (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        @type  module:   pida.module
        @param module:   (Optional, Def=None) Pointer to parent module container
        '''

        # GHETTO - we want to store the actual function to function edge start address.
        self.outbound_eas     = {}

        self.depth            = depth
        self.analysis         = analysis
        self.module           = module
        self.id               = None
        self.ea_start         = None
        self.ea_end           = None
        self.name             = None
        self.is_import        = False
        self.flags            = None
        self.rpc_uuid         = None
        self.rpc_opcode       = None
        self.saved_reg_size   = 0
        self.frame_size       = 0
        self.ret_size         = 0
        self.local_vars       = {}
        self.local_var_size   = 0
        self.num_local_vars   = 0
        self.args             = {}
        self.arg_size         = 0
        self.num_args         = 0
        self.chunks           = []
        self.ext              = {}
        self.num_instructions = 0

        # convenience alias.
        self.basic_blocks = self.nodes

        # grab the ida function and frame structures.
        func_struct  = get_func(ea_start)
        frame_struct = get_frame(func_struct)

        # grab the function flags.
        self.flags = GetFunctionFlags(ea_start)

        # if we're not in a "real" function. set the id and ea_start manually and stop analyzing.
        if not func_struct or self.flags & FUNC_LIB or self.flags & FUNC_STATIC:
            pgraph.graph.__init__(self, ea_start)
            pgraph.node.__init__ (self, ea_start)

            self.id         = ea_start
            self.ea_start   = ea_start
            self.ea_end     = ea_start
            self.name       = get_name(ea_start, ea_start)
            self.is_import  = True

            return

        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self, func_struct.startEA)
        pgraph.node.__init__ (self, func_struct.startEA)

        self.id             = func_struct.startEA
        self.ea_start       = func_struct.startEA
        self.ea_end         = PrevAddr(func_struct.endEA)
        self.name           = GetFunctionName(self.ea_start)
        self.saved_reg_size = func_struct.frregs
        self.frame_size     = get_frame_size(func_struct)
        self.ret_size       = get_frame_retsize(func_struct)
        self.local_var_size = func_struct.frsize
        self.chunks         = [(self.ea_start, self.ea_end)]

        self.__init_args_and_local_vars__()

        if self.depth & DEPTH_BASIC_BLOCKS:
            self.__init_basic_blocks__()


    ####################################################################################################################
    def __init_args_and_local_vars__ (self):
        '''
        Calculate the total size of arguments, # of arguments and # of local variables. Update the internal class member
        variables appropriately.
        '''

        # grab the ida function and frame structures.
        func_struct  = get_func(self.ea_start)
        frame_struct = get_frame(func_struct)

        if not frame_struct:
            return

        argument_boundary = self.local_var_size + self.saved_reg_size + self.ret_size
        frame_offset      = 0

        for i in xrange(0, frame_struct.memqty):
            end_offset = frame_struct.get_member(i).soff

            if i == frame_struct.memqty - 1:
                begin_offset = frame_struct.get_member(i).eoff
            else:
                begin_offset = frame_struct.get_member(i+1).soff

            frame_offset += (begin_offset - end_offset)

            # grab the name of the current local variable or argument.
            name = get_member_name(frame_struct.get_member(i).id)

            if name == None:
                continue

            if frame_offset > argument_boundary:
                self.args[end_offset] = name
            else:
                # if the name starts with a space, then ignore it as it is either the stack saved ebp or eip.
                # XXX - this is a pretty ghetto check.
                if not name.startswith(" "):
                    self.local_vars[end_offset] = name

        self.arg_size       = frame_offset - argument_boundary
        self.num_args       = len(self.args)
        self.num_local_vars = len(self.local_vars)


    ####################################################################################################################
    def __init_basic_blocks__ (self):
        '''
        Enumerate the basic block boundaries for the current function and store them in a graph structure.
        
        '''
        import copy
        self.chunks = self.__init_collect_function_chunks__()
        contained_heads = sum([[ea for ea in Heads(chunk_start, chunk_end)] for (chunk_start, chunk_end) in self.chunks],list())
        blocks = []        
        edges = []
        
        for (chunk_start, chunk_end) in self.chunks:

            curr_start = chunk_start
            # enumerate the nodes.
            for ea in Heads(chunk_start, chunk_end):
                # ignore data heads.
                if not isCode(GetFlags(ea)):
                    curr_start = NextNotTail(ea)
                    continue

                next_ea       = NextNotTail(ea)
                branches_to_next = self._branches_to(next_ea)       
                branches_from = self._branches_from(ea)
                is_retn = idaapi.is_ret_insn(ea)
                
                if is_retn or not isCode(GetFlags(next_ea)):
                    blocks.append((curr_start,ea))
                    curr_start = next_ea  #this will be handled if still not code
                    
        
                elif len(branches_from) > 0:
                    blocks.append((curr_start,ea))
                    curr_start = next_ea
                    
                    for branch in branches_from:
                        if branch not in contained_heads:
                            continue
                        if len(branches_from) == 1:  color = 0x0000FF
                        elif branch == next_ea:      color = 0xFF0000
                        else:                        color = 0x00FF00
                        edges.append((curr_start, branch, color))
                 
                elif len(branches_to_next)> 0:
                    blocks.append((curr_start,ea))
                    curr_start = next_ea
                    # draw an "implicit" branch.
                    edges.append((ea, next_ea, 0x0000FF))
                    
        basicBlocks = [basic_block(bs,be,self.depth, self.analysis, self)\
                        for (bs,be) in blocks]
        map(self.add_node,basicBlocks)
        
        for (src, dst, color) in edges:
            edge = pgraph.edge(src, dst)
            edge.color = color
            self.add_edge(edge)


    ####################################################################################################################
    def __init_collect_function_chunks__ (self):
        '''
        Generate and return the list of function chunks (including the main one) for the current function. Ripped from
        idb2reml (Ero Carerra).

        @rtype:  List
        @return: List of function chunks (start, end tuples) for the current function.
        '''

        chunks   = []
        iterator = func_tail_iterator_t(get_func(self.ea_start))
        status   = iterator.main()

        while status:
            chunk = iterator.chunk()
            chunks.append((chunk.startEA, chunk.endEA))
            status = iterator.next()

        return chunks


    ####################################################################################################################
    def _branches_from (self, ea):
        '''
        Enumerate and return the list of branches from the supplied address, *including* the next logical instruction.
        Part of the reason why we even need this function is that the "flow" argument to CodeRefsFrom does not appear
        to be functional.

        @type  ea: DWORD
        @param ea: Effective address of instruction to enumerate jumps from.

        @rtype:  List
        @return: List of branches from the specified address.
        '''

        if is_call_insn(ea):
            return []

        xrefs = list(CodeRefsFrom(ea, 1))

        # if the only xref from ea is next ea, then return nothing.
        if len(xrefs) == 1 and xrefs[0] == NextNotTail(ea):
            xrefs = []

        return xrefs


    ####################################################################################################################
    def _branches_to (self, ea):
        '''
        Enumerate and return the list of branches to the supplied address, *excluding* the previous logical instruction.
        Part of the reason why we even need this function is that the "flow" argument to CodeRefsTo does not appear to
        be functional.

        @type  ea: DWORD
        @param ea: Effective address of instruction to enumerate jumps to.

        @rtype:  List
        @return: List of branches to the specified address.
        '''

        xrefs        = []
        prev_ea      = PrevNotTail(ea)
        prev_code_ea = prev_ea

        while not isCode(GetFlags(prev_code_ea)):
            prev_code_ea = PrevNotTail(prev_code_ea)

        for xref in list(CodeRefsTo(ea, 1)):
            if not is_call_insn(xref) and xref not in [prev_ea, prev_code_ea]:
                xrefs.append(xref)

        return xrefs


    ####################################################################################################################
    def find_basic_block (self, ea):
        '''
        Locate and return the basic block that contains the specified address.

        @type  ea: DWORD
        @param ea: An address within the basic block to find

        @rtype:  pida.basic_block
        @return: The basic block that contains the given address or None if not found.
        '''

        for bb in self.nodes.values():
            if bb.ea_start <= ea <= bb.ea_end:
                return bb

        return None


    ####################################################################################################################
    def render_node_gml (self, graph):
        '''
        Overload the default node.render_node_gml() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label  = "<span style='font-family: Courier New; font-size: 10pt; color: #000000'>"
        self.label += "<p><font color=#004080><b>%08x %s</b></font></p>" % (self.ea_start, self.name)

        self.gml_height = 100
        self.gml_width  = (len(self.name) + 10) * 10

        if not self.is_import:
            self.label += "<b>size</b>: <font color=#FF8040>%d</font><br>" % (self.ea_end - self.ea_start)
            self.label += "<b>arguments</b>:<br>"

            for key, arg in self.args.items():
                self.label += "&nbsp;&nbsp;&nbsp;&nbsp;[%02x]%s<br>" % (key, arg)

                required_width = (len(arg) + 10) * 10

                if required_width > self.gml_width:
                    self.gml_width = required_width

                self.gml_height += 20

            self.label += "<b>local variables</b>:<br>"

            for key, var in self.local_vars.items():
                self.label += "&nbsp;&nbsp;&nbsp;&nbsp;[%02x] %s<br>" % (key, var)

                required_width = (len(var) + 10) * 10

                if required_width > self.gml_width:
                    self.gml_width = required_width

                self.gml_height += 20

        self.label += "</span>"

        return super(function, self).render_node_gml(graph)


    ####################################################################################################################
    def render_node_graphviz (self, graph):
        '''
        Overload the default node.render_node_graphviz() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  pydot.Node()
        @return: Pydot object representing node
        '''

        self.shape = "ellipse"

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_graphviz(graph)


    ####################################################################################################################
    def render_node_udraw (self, graph):
        '''
        Overload the default node.render_node_udraw() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  String
        @return: Contents of rendered node.
        '''

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_udraw(graph)


    ####################################################################################################################
    def render_node_udraw_update (self):
        '''
        Overload the default node.render_node_udraw_update() routine to create a custom label. Pass control to the
        default node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_udraw_update()