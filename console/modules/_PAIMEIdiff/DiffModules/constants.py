#
# $Id: constants.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class constants:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 1             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL | BASIC_BLOCK_LEVEL   # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Constants"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Constants module uses the constants in the functions as signatures"
        self.date        = "09/22/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_LOW
        
        
        self.parent.register_match_function(    self.match_function_by_const,    self )   # register a function matching routine
        self.parent.register_match_basic_block( self.match_basic_block_by_const, self )   # register a basic block matching routine
        self.parent.register_diff_function(     self.diff_function_by_const,     self )   # register a function diffing routine
        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_const(self, function_a, function_b):
        if len(function_a.ext["PAIMEIDiffFunction"].refs_constants) <= 1 or len(function_b.ext["PAIMEIDiffFunction"].refs_constants) <= 1:
            return 0
        if len(function_a.ext["PAIMEIDiffFunction"].refs_constants) != len(function_b.ext["PAIMEIDiffFunction"].refs_constants):
            return 0
        matched = 0
        for constant_a in function_a.ext["PAIMEIDiffFunction"].refs_constants:
            for constant_b in function_b.ext["PAIMEIDiffFunction"].refs_constants:
                if constant_a == constant_b:
                    matched = 1
                    break
            if not matched:
                return 0
            matched = 0
        return 1
        
    def match_basic_block_by_const(self, bb_a, bb_b):
        if len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_constants) <= 1 or len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_constants) <= 1:
            if bb_a.num_instructions < 4 or bb_b.num_instructions < 4:
                return 0
        matched = 0
        
        if len(bb_a.ext["PAIMEIDiffBasicBlock"].refs_constants) != len(bb_b.ext["PAIMEIDiffBasicBlock"].refs_constants):
            return 0
            
        for constant_a in bb_a.ext["PAIMEIDiffBasicBlock"].refs_constants:
            for constant_b in bb_b.ext["PAIMEIDiffBasicBlock"].refs_constants:
                if constant_a == constant_b:
                    matched = 1
                    break
            if not matched:
                return 0
            matched = 0
        return 1   
        
    def diff_function_by_const(self, function_a, function_b):
        if len(function_a.ext["PAIMEIDiffFunction"].refs_constants) <= 1 or len(function_b.ext["PAIMEIDiffFunction"].refs_constants) <= 1:
            return 0
        matched = 0
        if len(function_a.ext["PAIMEIDiffFunction"].refs_constants) != len(function_b.ext["PAIMEIDiffFunction"].refs_constants):
            return 1
            
        for constant_a in function_a.ext["PAIMEIDiffFunction"].refs_constants:
            for constant_b in function_b.ext["PAIMEIDiffFunction"].refs_constants:
                if constant_a == constant_b:
                    matched = 1
                    break
            if not matched:
                return 1
            matched = 0
        return 0
        
