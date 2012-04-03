#
# PIDA Instruction
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: instruction.py 257 2011-07-20 14:38:59Z chanleeyee@gmail.com $
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
    import idautils
    from idaapi   import *
    from idautils import *
    from idc      import *
except:
    pass

from defines import *

class instruction:
    '''
    '''

    ea             = None                          # effective address of instruction
    analysis       = None                          # analysis options
    basic_block    = None                          # pointer to parent container
    disasm         = None                          # sanitized disassembly at instruction
    comment        = ""                            # comment at instruction EA

    bytes          = []                            # instruction raw bytes, mnemonic and operands
    mnem           = None
    op1            = None
    op2            = None
    op3            = None

    refs_string    = None                          # string, if any, that this instruction references
    refs_api       = None                          # known API, if any, that this instruction references
    refs_arg       = None                          # argument, if any, that this instruction references
    refs_constant  = None                          # constant value, if any, that this instruction references
    refs_var       = None                          # local variable, if any, that this instruction references

    ext            = {}

    ####################################################################################################################
    def __init__ (self, ea, analysis=0, basic_block=None):
        '''
        Analyze the instruction at ea.

        @see: defines.py

        @type  ea:          DWORD
        @param ea:          Effective address of instruction to analyze
        @type  analysis:    Integer
        @param analysis:    (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        @type  basic_block: pgraph.basic_block
        @param basic_block: (Optional, Def=None) Pointer to parent basic block container
        '''

        self.ea          = ea                            # effective address of instruction
        self.analysis    = analysis                      # analysis options
        self.basic_block = basic_block                   # pointer to parent container
        self.disasm      = self.get_disasm(ea)           # sanitized disassembly at instruction
        self.comment     = Comment(ea)
        self.ext         = {}

        # raw instruction bytes.
        self.bytes = []

        # instruction mnemonic and operands.
        self.mnem = GetMnem(ea)
        self.op1  = GetOpnd(ea, 0)
        self.op2  = GetOpnd(ea, 1)
        self.op3  = GetOpnd(ea, 2)

        for address in xrange(ea, ItemEnd(ea)):
            self.bytes.append(Byte(address))

        # XXX - this is a dirty hack to determine if and any API reference.
        xref  = Dfirst(self.ea)
        flags = GetFunctionFlags(xref)

        if xref == BADADDR:
            xref  = get_first_cref_from(ea)
            flags = GetFunctionFlags(xref)

        if SegName(xref) == ".idata":
            name = get_name(xref, xref)

            if name and get_name_ea(BADADDR, name) != BADADDR:
                self.refs_api = (get_name_ea(BADADDR, name), name)

        self.refs_string   = None
        self.refs_arg      = self._get_arg_ref()
        self.refs_constant = self._get_constant_ref()
        self.refs_var      = self._get_var_ref()


    ####################################################################################################################
    def _get_arg_ref (self):
        '''
        Return the stack offset of the argument referenced, if any, by the instruction.

        @author: Peter Silberman

        @rtype:  Mixed
        @return: Referenced argument stack offset or None.
        '''

        func = get_func(self.ea)

        if not func:
            return None

        # determine if either of the operands references a stack offset.
        op_num = 0
        offset = calc_stkvar_struc_offset(func, self.ea, 0)

        if offset == BADADDR:
            op_num = 1
            offset = calc_stkvar_struc_offset(func, self.ea, 1)

            if offset == BADADDR:
                return None

        # for some reason calc_stkvar_struc_offset detects constant values as an index into the stack struct frame. we
        # implement this check to ignore this false positive.
        # XXX - may want to look into why this is the case later.
        if self._get_constant_ref(op_num):
            return None

        if self.basic_block.function.args.has_key(offset):
            return self.basic_block.function.args[offset]

        return None


    ####################################################################################################################
    def _get_constant_ref (self, opnum=0):
        '''
        Return the constant value, if any, reference by the instruction.

        @author: Peter Silberman

        @rtype:  Mixed
        @return: Integer value of referenced constant, otherwise None.
        '''

        if idaapi.IDA_SDK_VERSION >=600:
            instruction = idaapi.cmd.ea
        else:
            instruction = idaapi.get_current_instruction()

        if not instruction:
            return None

        if opnum:
            if idaapi.IDA_SDK_VERSION >=600:
                op0 = idautils.DecodeInstruction(instruction)[opnum]
            else:
                op0 = idaapi.get_instruction_operand(instruction, opnum)

            if op0.value and op0.type == o_imm and GetStringType(self.ea) == None:
                return op0.value

        else:
            if idaapi.IDA_SDK_VERSION >=600:
                op0 = idautils.DecodeInstruction(instruction)[0]
            else:
                op0 = idaapi.get_instruction_operand(instruction, 0)

            if op0.value and op0.type == o_imm and GetStringType(self.ea) == None:
                return op0.value

            if idaapi.IDA_SDK_VERSION >=600:
                op1 = idautils.DecodeInstruction(instruction)[1]
            else:
                op1 = idaapi.get_instruction_operand(instruction, 1)

            if op1.value and op1.type == o_imm and GetStringType(self.ea) == None:
                return op1.value

        return None


    ####################################################################################################################
    def _get_var_ref (self):
        '''
        Return the stack offset of the local variable referenced, if any, by the instruction.

        @author: Peter Silberman

        @rtype:  Mixed
        @return: Referenced local variable stack offset or None.
        '''

        func = get_func(self.ea)

        if not func:
            return None

        # determine if either of the operands references a stack offset.
        op_num = 0
        offset = calc_stkvar_struc_offset(func, self.ea, 0)

        if offset == BADADDR:
            op_num = 1
            offset = calc_stkvar_struc_offset(func, self.ea, 1)

            if offset == BADADDR:
                return None

        if self.basic_block.function.local_vars.has_key(offset):
            return self.basic_block.function.local_vars[offset]

        return None


    ####################################################################################################################
    def flag_dependency (first_instruction, second_instruction):
        '''
        Determine if one instruction can affect flags used by the other instruction.

        @author: Cameron Hotchkies

        @type   first_instruction:  instruction
        @param  first_instruction:  The first instruction to check
        @type   second_instruction: instruction
        @param  second_instruction: The second instruction to check

        @rtype: Integer
        @return: 0 for no effect, 1 for first affects second, 2 for second affects first, 3 for both can affect
        '''

        if first_instruction.mnem in instruction.FLAGGED_OPCODES and second_instruction.mnem in instruction.FLAGGED_OPCODES:
            ret_val = 0

            # if neither opcodes set any flags, they can be ignored
            if instruction.FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__SET_MASK > 0 and \
               instruction.FLAGGED_OPCODES[second_instruction.mnem] & instruction.__SET_MASK > 0:
                return 0

            setter = instruction.FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__SET_MASK
            tester = instruction.FLAGGED_OPCODES[second_instruction.mnem] & instruction.__TEST_MASK

            if setter & (tester << 16) > 0:
                ret_val += 1

            setter = instruction.FLAGGED_OPCODES[second_instruction.mnem] & instruction.__SET_MASK
            tester = instruction.FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__TEST_MASK

            if setter & (tester << 16) > 0:
                ret_val += 2

            return ret_val

        return 0


    ####################################################################################################################
    def get_disasm (self, ea):
        '''
        A GetDisasm() wrapper that strips comments and extraneous whitespace.

        @type  ea: DWORD
        @param ea: Effective address of instruction to analyze

        @rtype:  String
        @return: Sanitized disassembly at ea.
        '''

        disasm = GetDisasm(ea)

        # if the disassembled line contains a comment. then strip it and the trailing whitespace.
        if disasm.count(";"):
            disasm = disasm[0:disasm.index(";")].rstrip(" ")

        # shrink whitespace.
        while disasm.count("  "):
            disasm = disasm.replace("  ", " ")

        return disasm


    ####################################################################################################################
    def get_string_reference (self, ea):
        '''
        If the specified instruction references a string, get and return the contents of that string.
        Currently supports:

        @todo: XXX - Add more supported string types.

        @type  ea: DWORD
        @param ea: Effective address of instruction to analyze

        @rtype:  Mixed
        @return: ASCII representation of string referenced from ea if found, None otherwise.
        '''

        dref = Dfirst(ea)
        s    = ""

        if dref == BADADDR:
            return None

        string_type = GetStringType(dref)

        if string_type == ASCSTR_C:
            while True:
                byte = Byte(dref)

                if byte == 0 or byte < 32 or byte > 126:
                    break

                s    += chr(byte)
                dref += 1

        return s


    ####################################################################################################################
    def is_conditional_branch (self):
        '''
        Check if the instruction is a conditional branch. (x86 specific)

        @author: Cameron Hotchkies

        @rtype:  Boolean
        @return: True if the instruction is a conditional branch, False otherwise.
        '''

        if len(self.mnem) and self.mnem[0] == 'j' and self.mnem != "jmp":
            return True

        return False


    ####################################################################################################################
    def overwrites_register (self, register):
        '''
        Indicates if the given register is modified by this instruction. This does not check for all modifications,
        just lea, mov and pop into the specific register.

        @author: Cameron Hotchkies

        @type   register: String
        @param  register: The text representation of the register

        @rtype: Boolean
        @return: True if the register is modified
        '''

        if self.mnem == "mov" or self.mnem == "pop" or self.mnem == "lea":
            if self.op1 == register:
                return True

        if self.mnem == "xor" and self.op1 == self.op2 and self.op1 == register:
            return True

        if register == "eax" and self.mnem == "call":
            return True

        return False


    ####################################################################################################################
    ### constants for flag-using instructions (ripped from bastard)
    ###

    __TEST_CARRY  =   0x0001
    __TEST_ZERO   =   0x0002
    __TEST_OFLOW  =   0x0004
    __TEST_DIR    =   0x0008
    __TEST_SIGN   =   0x0010
    __TEST_PARITY =   0x0020
    __TEST_NCARRY =   0x0100
    __TEST_NZERO  =   0x0200
    __TEST_NOFLOW =   0x0400
    __TEST_NDIR   =   0x0800
    __TEST_NSIGN  =   0x1000
    __TEST_NPARITY=   0x2000
    __TEST_SFEQOF =   0x4000
    __TEST_SFNEOF =   0x8000
    __TEST_ALL    =   __TEST_CARRY | __TEST_ZERO |  __TEST_OFLOW | __TEST_SIGN |  __TEST_PARITY

    __SET_CARRY   =   0x00010000
    __SET_ZERO    =   0x00020000
    __SET_OFLOW   =   0x00040000
    __SET_DIR     =   0x00080000
    __SET_SIGN    =   0x00100000
    __SET_PARITY  =   0x00200000
    __SET_NCARRY  =   0x01000000
    __SET_NZERO   =   0x02000000
    __SET_NOFLOW  =   0x04000000
    __SET_NDIR    =   0x08000000
    __SET_NSIGN   =   0x10000000
    __SET_NPARITY =   0x20000000
    __SET_SFEQOF  =   0x40000000
    __SET_SFNEOF  =   0x80000000
    __SET_ALL     =   __SET_CARRY | __SET_ZERO |  __SET_OFLOW | __SET_SIGN |  __SET_PARITY

    __TEST_MASK   =   0x0000FFFF
    __SET_MASK    =   0xFFFF0000


    ####################################################################################################################
    ### flag-using instructions in a dictionary (ripped from bastard)
    ###

    FLAGGED_OPCODES = \
    {
        "add"      : __SET_ALL,
        "or"       : __SET_ALL,
        "adc"      : __TEST_CARRY | __SET_ALL,
        "sbb"      : __TEST_CARRY | __SET_ALL,
        "and"      : __SET_ALL,
        "daa"      : __TEST_CARRY | __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "sub"      : __SET_ALL,
        "das"      : __TEST_CARRY | __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "xor"      : __SET_ALL,
        "aaa"      : __SET_CARRY,
        "cmp"      : __SET_ALL,
        "aas"      : __SET_CARRY,
        "inc"      : __SET_ZERO | __SET_OFLOW | __SET_SIGN | __SET_PARITY,
        "dec"      : __SET_ZERO | __SET_OFLOW | __SET_SIGN | __SET_PARITY,
        "arpl"     : __SET_ZERO,
        "imul"     : __SET_CARRY | __SET_OFLOW,
        "jo"       : __TEST_OFLOW,
        "jno"      : __TEST_NOFLOW,
        "jbe"      : __TEST_CARRY | __TEST_ZERO,
        "ja"       : __TEST_NCARRY | __TEST_NZERO,
        "js"       : __TEST_SIGN,
        "jns"      : __TEST_NSIGN,
        "jl"       : __TEST_SFNEOF,
        "jge"      : __TEST_SFEQOF,
        "jle"      : __TEST_ZERO | __TEST_SFNEOF,
        "jg"       : __TEST_NZERO | __TEST_SFEQOF,
        "test"     : __SET_ALL,
        "sahf"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "into"     : __TEST_OFLOW,
        "iret"     : __SET_ALL,
        "aam"      : __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "aad"      : __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "cmc"      : __SET_CARRY,
        "clc"      : __SET_NCARRY,
        "stc"      : __SET_CARRY,
        "cld"      : __SET_NDIR,
        "std"      : __SET_DIR,
        "lsl"      : __SET_ZERO,
        "ucomiss"  : __SET_ALL,
        "comiss"   : __SET_ALL,
        "cmovo"    : __TEST_OFLOW,
        "cmovno"   : __TEST_NOFLOW,
        "cmovbe"   : __TEST_CARRY | __TEST_ZERO,
        "cmova"    : __TEST_NCARRY | __TEST_NZERO,
        "cmovs"    : __TEST_SIGN,
        "cmovns"   : __TEST_NSIGN,
        "cmovl"    : __TEST_OFLOW | __TEST_SIGN,
        "cmovge"   : __TEST_OFLOW | __TEST_SIGN,
        "cmovle"   : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "cmovg"    : __TEST_OFLOW | __TEST_SIGN | __TEST_NZERO,
        "seto"     : __TEST_OFLOW,
        "setno"    : __TEST_OFLOW,
        "setbe"    : __TEST_CARRY | __TEST_ZERO,
        "seta"     : __TEST_CARRY | __TEST_ZERO,
        "sets"     : __TEST_SIGN,
        "setns"    : __TEST_SIGN,
        "setl"     : __TEST_OFLOW | __TEST_SIGN,
        "setge"    : __TEST_OFLOW | __TEST_SIGN,
        "setle"    : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "setg"     : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "bt"       : __SET_CARRY,
        "shld"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "rsm"      : __SET_ALL,
        "bts"      : __SET_CARRY,
        "shrd"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "cmpxchg"  : __SET_ALL,
        "btr"      : __SET_CARRY,
        "btc"      : __SET_CARRY,
        "bsf"      : __SET_ZERO,
        "bsr"      : __SET_ZERO,
        "xadd"     : __SET_ALL,
        "verr"     : __SET_ZERO,
        "verw"     : __SET_ZERO,
        "rol"      : __SET_CARRY | __SET_OFLOW,
        "ror"      : __SET_CARRY | __SET_OFLOW,
        "rcl"      : __TEST_CARRY | __SET_CARRY | __SET_OFLOW,
        "rcr"      : __TEST_CARRY | __SET_CARRY | __SET_OFLOW,
        "shl"      : __SET_ALL,
        "shr"      : __SET_ALL,
        "sal"      : __SET_ALL,
        "sar"      : __SET_ALL,
        "neg"      : __SET_ALL,
        "mul"      : __SET_CARRY | __SET_OFLOW,
        "fcom"     : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomp"    : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomp"    : __TEST_CARRY | __SET_CARRY | __SET_PARITY,
        "fcmovb"   : __TEST_CARRY,
        "fcmove"   : __TEST_ZERO,
        "fcmovbe"  : __TEST_CARRY | __TEST_ZERO,
        "fcmovu"   : __TEST_PARITY,
        "fcmovnb"  : __TEST_NCARRY,
        "fcmovne"  : __TEST_NZERO,
        "fcmovnbe" : __TEST_NCARRY | __TEST_NZERO,
        "fcmovnu"  : __TEST_NPARITY,
        "fcomi"    : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomip"   : __SET_CARRY | __SET_ZERO | __SET_PARITY
    }
