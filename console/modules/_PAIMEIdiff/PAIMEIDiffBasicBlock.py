#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: PAIMEIDiffBasicBlock.py 194 2007-04-05 15:31:53Z cameron $
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

import md5
import pida
import PAIMEIDiffInstruction



class PAIMEIDiffBasicBlock:
    def __init__(self, basic_block, function, bb_num, parent):
        self.pida_basic_block   = basic_block                           # reference to the pida basic block class                                                   
        self.pida_function      = function                              # reference to the pida function class
        
        self.spp                = 1                                     # initially spp value is given 1
        self.smart_md5          = ""            
        self.changed            = 0                                     # flag used in diffing    
        self.match_method       = ""                                    # method used to match the basic blocks
        self.matched            = 0                                     # flag used to indicated the basic block is matched
        self.matched_ea         = None                                  # the ea that corresponds to the match basic block
        self.matched_bb         = None                                  # a reference to the basic block class that this basic block as matched to
        self.ignore             = 0                                     # an ignore flag to indicate that the basic block is to be ignored
        self.different          = 0                                     # a flag to indicate the basic block is different
        self.num_calls          = 0                                     # number of calls in the basic block
        self.num_instructions   = 0                                     # number of instructions in the basic block
        self.refs_api           = []                                    # a list of api's referenced within the basic block
        self.refs_constants     = []                                    # a list of constants that are referenced within the basic block
        self.refs_vars          = []                                    # a list of vars referenced in the basic block
        self.refs_args          = []                                    # a list of args referenced in the basic block
        self.ea_end             = self.pida_basic_block.ea_end          # the ea end of the basic block
        self.ea_start           = self.pida_basic_block.ea_start        # the ea start of the basic block
        self.size               = self.pida_basic_block.ea_end - self.pida_basic_block.ea_start # the size of the basic block
        self.eci                = None                                  # the edge call instruction count
        self.crc                = 0xFFFFFFFFL                           # initially crc value
        self.refs_strings       = []                                    # a list of strings referenced in the basic block
        self.touched            = 0 
        self.parent             = parent
        
        index = bb_num
        
        self.num_instructions = self.pida_basic_block.num_instructions
        
        for ii in self.pida_basic_block.sorted_instructions():

            ii.ext["PAIMEIDiffInstruction"] = PAIMEIDiffInstruction.PAIMEIDiffInstruction(ii, self.pida_basic_block, self.pida_function)

            #Calculate spp
            self.spp *= ii.ext["PAIMEIDiffInstruction"].prime

            #Fill out distance entry/exit points
            ii.ext["PAIMEIDiffInstruction"].distance_entry = index
            ii.ext["PAIMEIDiffInstruction"].distance_exit = self.pida_function.num_instructions - index
            index+=1

            # count calls
            if ii.mnem == "call":
                self.num_calls +=1
            # store api calls
            if ii.refs_api:
                self.refs_api.append( ii.refs_api )
            # store constants
            if ii.refs_constant != None:
                self.refs_constants.append(ii.refs_constant)
            # store references to args
            if ii.refs_arg:
                self.refs_args.append(ii.refs_arg)
            # store references to vars
            if ii.refs_var:
                self.refs_vars.append(ii.refs_var)
            
            # store references to strings
            if ii.refs_string:
                self.refs_strings.append(ii.refs_string)
        
        # generate eci signature                
        self.eci = ( self.pida_function.edges_from(self.pida_basic_block.ea_start), self.num_calls, len(self.pida_basic_block.instructions.values()))
        
        # generate smart md5 signature
        self.generate_smart_md5()
        
        # calculate the crc signature
        #self.crc_calculate()
        
    ####################################################################################################################    
    def generate_smart_md5(self):
        '''
        Generate the smart md5 signature for the function
        '''
        alpha = []
        for inst in self.pida_basic_block.sorted_instructions():
            instruction = inst.mnem
            if len(instruction) <= 1 or instruction == "nop":
                continue
            elif instruction == "cmp" or instruction == "test":
                alpha.append("comparision")
            elif instruction[0] == "j":
                if instruction == "jg" or instruction == "jge" or instruction == "jl" or instruction == "jle" or instruction == "jng" or instruction == "jnge" or instruction == "jnl" or instruction == "jnle" or instruction == "jno" or instruction == "jns" or instruction == "jo" or instruction == "js":
                    alpha.append("jmp_signed")
                else:
                    alpha.append("jmp_unsigned")
            else:
                alpha.append(instruction)
        alpha.sort()
        digest_str = ""
        m = md5.new()
        for char in alpha:
            digest_str += char
        m.update( digest_str ) 
        self.smart_md5 = m.hexdigest()

        
    ####################################################################################################################
    def crc_calculate(self):
        '''
        Loop through the function and create to create CRC sig
        '''
        #for bb in self.pida_function.sorted_nodes():
        for inst in self.pida_basic_block.sorted_instructions():                    
            size = len(inst.bytes)
            i = 0
            while i < len(inst.bytes):
                byte = inst.bytes[i]
                self.crc = (self.crc >> 8) ^ self.parent.crc_table[ ( self.crc ^ byte ) & 0xFFL ]
                i+=1
        self.crc = self.crc ^ 0xFFFFFFFFL