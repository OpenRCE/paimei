#
# $Id: arg_var.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class arg_var:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 1             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL | BASIC_BLOCK_LEVEL # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Arg_Var"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Stack Frame module uses the functions stack frame as a signature"
        self.date        = "09/22/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_LOW        
        
        self.parent.register_match_function(    self.match_function_by_stack_arg_var,    self )   # register a function matching routine
        self.parent.register_diff_function(     self.diff_function_by_stack_arg_var,     self )   # register a function diffing routine
        self.parent.register_match_basic_block( self.match_basic_block_by_stack_arg_var, self )   # register a basic block matching routine

        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_stack_arg_var(self, function_a, function_b):
        if function_a.arg_size  == function_b.arg_size and function_a.num_args == function_b.num_args:
            if function_a.local_var_size == function_b.local_var_size and function_a.num_local_vars == function_b.num_local_vars:
                return 1
        return 0
        
    def diff_function_by_stack_arg_var(self, function_a, function_b):
        if function_a.arg_size  == function_b.arg_size and function_a.num_args == function_b.num_args:
            if function_a.local_var_size == function_b.local_var_size and function_a.num_local_vars == function_b.num_local_vars:
                return 0
        return 1
    def match_basic_block_by_stack_arg_var(self, bb_a, bb_b):
        if len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_args) == 0 and len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_vars) == 0:
            return 0
        if len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_args) == 0 and len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_vars) == 0:
            return 0
        if len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_args) == len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_args) and len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_vars) == len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_vars):
            return 1
        else:
            return 0
            