#
# PIDA Basic Block
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: basic_block.py 194 2007-04-05 15:31:53Z cameron $
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

from instruction import *
from defines     import *

class basic_block (pgraph.node):
    '''
    '''

    id               = None
    ea_start         = None
    ea_end           = None
    depth            = None
    analysis         = None
    function         = None
    instructions     = {}
    num_instructions = 0
    ext              = {}

    ####################################################################################################################
    def __init__ (self, ea_start, ea_end, depth=DEPTH_FULL, analysis=ANALYSIS_NONE, function=None):
        '''
        Analyze the basic block from ea_start to ea_end.

        @see: defines.py

        @type  ea_start: DWORD
        @param ea_start: Effective address of start of basic block (inclusive)
        @type  ea_end:   DWORD
        @param ea_end:   Effective address of end of basic block (inclusive)
        @type  depth:    Integer
        @param depth:    (Optional, Def=DEPTH_FULL) How deep to analyze the module
        @type  analysis: Integer
        @param analysis: (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        @type  function: pida.function
        @param function: (Optional, Def=None) Pointer to parent function container
        '''

        # run the parent classes initialization routine first.
        super(basic_block, self).__init__(ea_start)

        heads = [head for head in Heads(ea_start, ea_end + 1) if isCode(GetFlags(head))]

        self.id               = ea_start
        self.ea_start         = ea_start
        self.ea_end           = ea_end
        self.depth            = depth
        self.analysis         = analysis
        self.function         = function
        self.num_instructions = len(heads)
        self.instructions     = {}
        self.ext              = {}

        # convenience alias.
        self.nodes = self.instructions

        # bubble up the instruction count to the function. this is in a try except block to catch situations where the
        # analysis was not bubbled down from a function.
        try:
            self.function.num_instructions += self.num_instructions
        except:
            pass

        if self.depth & DEPTH_INSTRUCTIONS:
            for ea in heads:
                self.instructions[ea] = instr = instruction(ea, self.analysis, self)


    ####################################################################################################################
    def overwrites_register (self, register):
        '''
        Indicates if the given register is modified by this block.

        @type  register: String
        @param register: The text representation of the register

        @rtype:  Boolean
        @return: True if the register is modified by any instruction in this block.
        '''

        for ins in self.instructions.values():
            if ins.overwrites_register(register):
                return True

        return False


    ####################################################################################################################
    def ordered_instructions(self):
        '''
        TODO: deprecated by sorted_instructions().
        '''

        temp = [key for key in self.instructions.keys()]
        temp.sort()
        return [self.instructions[key] for key in temp]


    ####################################################################################################################
    def render_node_gml (self, graph):
        '''
        Overload the default node.render_node_gml() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label  = "<span style='font-family: Courier New; font-size: 10pt; color: #000000'>"
        self.label += "<p><font color=#004080><b>%08x</b></font></p>" % self.ea_start

        self.gml_height = 45

        for instruction in self.sorted_instructions():
            colored_instruction = instruction.disasm.split()

            if colored_instruction[0] == "call":
                colored_instruction[0] = "<font color=#FF8040>" + colored_instruction[0] + "</font>"
            else:
                colored_instruction[0] = "<font color=#004080>" + colored_instruction[0] + "</font>"

            colored_instruction = " ".join(colored_instruction)

            self.label += "<font color=#999999>%08x</font>&nbsp;&nbsp;%s<br>" % (instruction.ea, colored_instruction)

            try:    instruction_length = len(instruction.disasm)
            except: instruction_length = 0

            try:    comment_length = len(instruction.comment)
            except: comment_length = 0

            required_width = (instruction_length + comment_length + 10) * 10

            if required_width > self.gml_width:
                self.gml_width = required_width

            self.gml_height += 20

        self.label += "</span>"

        return super(basic_block, self).render_node_gml(graph)


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

        self.label = ""
        self.shape = "box"

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_graphviz(graph)


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

        self.label = ""

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_udraw(graph)


    ####################################################################################################################
    def render_node_udraw_update (self):
        '''
        Overload the default node.render_node_udraw_update() routine to create a custom label. Pass control to the
        default node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label = ""

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_udraw_update()


    ####################################################################################################################
    def sorted_instructions (self):
        '''
        Return a list of the instructions within the graph, sorted by id.

        @rtype:  List
        @return: List of instructions, sorted by id.
        '''

        instruction_keys = self.instructions.keys()
        instruction_keys.sort()

        return [self.instructions[key] for key in instruction_keys]