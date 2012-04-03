#
# $Id: size.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class size:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 1             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL | BASIC_BLOCK_LEVEL   # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Size"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Size uses the size of the function as a signature"
        self.date        = "09/22/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_LOW
        
        self.parent.register_match_function(    self.match_function_by_size,    self )   # register a function matching routine
        self.parent.register_match_basic_block( self.match_basic_block_by_size, self )   # register a basic block matching routine
        self.parent.register_diff_function(     self.diff_function_by_size,     self )   # register a function diffing routine
        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_size(self, function_a, function_b):
        if function_a.ext["PAIMEIDiffFunction"].size == function_b.ext["PAIMEIDiffFunction"].size:
            return 1
        else:
            return 0
        
    def match_basic_block_by_size(self, bb_a, bb_b):
        if bb_a.ext["PAIMEIDiffBasicBlock"].size == bb_b.ext["PAIMEIDiffBasicBlock"].size:
            return 1
        else:
            return 0    
        
    def diff_function_by_size(self, function_a, function_b):
        if function_a.ext["PAIMEIDiffFunction"].size != function_b.ext["PAIMEIDiffFunction"].size:
            return 1
        else:
            return 0
        
