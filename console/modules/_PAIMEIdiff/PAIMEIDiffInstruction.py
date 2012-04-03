#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: PAIMEIDiffInstruction.py 194 2007-04-05 15:31:53Z cameron $
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

import pida


prime_numbers = \
[
    2,       3,    5,    7,   11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   61,
    67,     71,   73,   79,   83,   89,   97,  101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,
    157,   163,  167,  173,  179,  181,  191,  193,  197,  199,  211,  223,  227,  229,  233,  239,  241,  251,
    257,   263,  269,  271,  277,  281,  283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,
    367,   373,  379,  383,  389,  397,  401,  409,  419,  421,  431,  433,  439,  443,  449,  457,  461,  463,
    467,   479,  487,  491,  499,  503,  509,  521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,
    599,   601,  607,  613,  617,  619,  631,  641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,
    709,   719,  727,  733,  739,  743,  751,  757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827,
    829,   839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,  937,  941,  947,  953,
    967,   971,  977,  983,  991,  997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
    1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481,
    1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601,
    1607, 1609, 1613, 1619
]
#
#modified by Peter
#
prime_jmp_unsigned = 1949      
prime_jmp_signed   = 1987      
prime_cmp          = 1999 


class PAIMEIDiffInstruction:
    def __init__(self, inst, basic_block, func):
        self.pida_instruction       = inst              # reference to the original pida instruction class
        self.pida_basic_block       = basic_block       # reference to the original pida basic block class
        self.function               = func              # reference to the original pida function class
        self.prime                  = 1                 # set prime to 1
        self.match_method           = ""                # set our match method to nothing (may not be used)
        self.matched                = 0                 # set our matched flag to zero
        self.matched_ea             = None              # set our matched_ea to None or BADADDR
        self.matched_instruction    = None              # set our matched_instruction to None
        self.distance_entry         = None              # set our distance entry to None
        self.distance_exit          = None              # set our distance exit to None
        self.get_prime()                                # get the prime representation of this instruction

    ####################################################################################################################
    def get_prime(self):
        #if the instruction is <= 1 then its invalid and just set the prime to 1
        if len(self.pida_instruction.mnem) <= 1:
            self.prime = 1
        elif self.pida_instruction.mnem == "cmp" or self.pida_instruction.mnem == "test":
            self.prime = prime_cmp
        elif self.pida_instruction.mnem == "jmp" or self.pida_instruction.mnem == "ret" or self.pida_instruction.mnem == "retn":
            self.prime = 1
        elif self.pida_instruction.mnem[0] == "j":
            if self.pida_instruction.mnem == "jg" or self.pida_instruction.mnem == "jge" or self.pida_instruction.mnem == "jl" or self.pida_instruction.mnem == "jle" or self.pida_instruction.mnem == "jng" or self.pida_instruction.mnem == "jnge" or self.pida_instruction.mnem == "jnl" or self.pida_instruction.mnem == "jnle" or self.pida_instruction.mnem == "jno" or self.pida_instruction.mnem == "jns" or self.pida_instruction.mnem == "jo" or self.pida_instruction.mnem == "js":
                self.prime = prime_jmp_signed
            else:
                self.prime = prime_jmp_unsigned
        else:  
            self.prime = prime_numbers[ self.pida_instruction.bytes[0] ] 