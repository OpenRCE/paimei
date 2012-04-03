#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: PAIMEIDiffFunction.py 194 2007-04-05 15:31:53Z cameron $
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

import PAIMEIDiffBasicBlock
import PAIMEIDiffInstruction
import pida
import time

class PAIMEIDiffFunction:
    def __init__(self, function, module, parent):
        self.pida_function      = function                  # a reference to the pida function class
        self.pida_module        = module                    # a reference to the pida module class
        self.matched            = 0                         # flag to indicate if the function was matched
        self.matched_ea         = None                      # stores the corresponding ea_start of the matched function
        self.matched_function   = None                      # stores the corresponding pida function class of the matched function
        self.match_method       = ""                        # the method used to match
        self.different          = 0                         # flag used to indicate if the function is different
        self.spp                = 1                         # the initial value of the SPP
        self.smart_md5          = ""                        # smart md5
        self.crc_table          = {}                        # the crc table 
        self.crc                = 0xFFFFFFFFL               # the crc signature of the whole function
        self.neci               = []                        # the neci of the function
        self.recursive          = []                        # not use atm
        self.num_calls          = 0                         # number of calls throughout the function
        self.size               = self.pida_function.ea_end - self.pida_function.ea_start   # size of the function
        self.refs_constants     = []                        # a list of constants referenced throughout the function
        self.refs_api           = []                        # a list of api calls referenced throughout the function
        self.refs_strings       = []                        # a list of strings referenced throughout the function
        self.num_bb_id          = 0                         # number of basic blocks identified and ignored

        count = 0
        self.crc_table = parent.crc_table
#        start = time.time()
        
        # fill in all the pertinent information needed for diffing
        for bb in self.pida_function.sorted_nodes():
            bb.ext["PAIMEIDiffBasicBlock"] = PAIMEIDiffBasicBlock.PAIMEIDiffBasicBlock(bb, self.pida_function, count, self)    
            self.smart_md5 += bb.ext["PAIMEIDiffBasicBlock"].smart_md5
            self.spp *= bb.ext["PAIMEIDiffBasicBlock"].spp
            count += len(bb.instructions)
            self.num_calls  += bb.ext["PAIMEIDiffBasicBlock"].num_calls
            if bb.ext["PAIMEIDiffBasicBlock"].refs_constants != None:
                for const in bb.ext["PAIMEIDiffBasicBlock"].refs_constants:
                    self.refs_constants.append( const )
            if bb.ext["PAIMEIDiffBasicBlock"].refs_api != None:
                for api in bb.ext["PAIMEIDiffBasicBlock"].refs_api:
                    self.refs_api.append( api )
            if bb.ext["PAIMEIDiffBasicBlock"].refs_strings != None:
                for s in bb.ext["PAIMEIDiffBasicBlock"].refs_strings:
                    self.refs_strings.append( s )


        self.neci = ( len(self.pida_function.nodes), len( self.pida_module.edges_from( self.pida_function.ea_start) ), self.num_calls, self.pida_function.num_instructions)
        self.crc_calculate()
#        parent.msg("Loaded %s PAIMEIDiffFunction in %.2f seconds." % (function.name, round(time.time() - start, 3) ) ) 

        
    ####################################################################################################################
    def crc_calculate(self):
        '''
        Loop through the function and create to create CRC sig
        '''
        crc = 0xFFFFFFFFL
        
        for bb in self.pida_function.sorted_nodes():
            crc = 0xFFFFFFFFL
            for inst in bb.sorted_instructions():                    
                size = len(inst.bytes)
                i = 0
                while i < len(inst.bytes):
                    byte = inst.bytes[i]
                    self.crc = (self.crc >> 8) ^ self.crc_table[ ( self.crc ^ byte ) & 0xFFL ]
                    crc = (crc >> 8) ^ self.crc_table[ ( crc ^ byte ) & 0xFFL ]
                    i+=1
            crc = crc ^ 0xFFFFFFFFL               
            bb.ext["PAIMEIDiffBasicBlock"].crc = crc
#            if bb.ext["PAIMEIDiffBasicBlock"].crc == crc:
#                print "CRC 0x%08x != CRC 0x%08x" % (crc, bb.ext["PAIMEIDiffBasicBlock"].crc)
        self.crc = self.crc ^ 0xFFFFFFFFL