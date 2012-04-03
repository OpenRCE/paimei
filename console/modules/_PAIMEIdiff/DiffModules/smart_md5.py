#
# $Id: smart_md5.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class smart_md5:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 1             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL | BASIC_BLOCK_LEVEL   # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Smart_MD5"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Smart MD5  module implements an algorithm that tokenizes the instructions to create a smart signature."
        self.date        = "09/08/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_HIGH
        
        self.parent.register_match_function(    self.match_function_by_smart_md5,    self )   # register a function matching routine
        self.parent.register_match_basic_block( self.match_basic_block_by_smart_md5, self )   # register a basic block matching routine
        self.parent.register_diff_function(     self.diff_function_by_smart_md5,     self )   # register a function diffing routine
        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_smart_md5(self, function_a, function_b):
        if not function_a.ext.has_key("PAIMEIDiffFunction") or not function_b.ext.has_key("PAIMEIDiffFunction"):
            return 0
        if function_a.ext["PAIMEIDiffFunction"].smart_md5 == function_b.ext["PAIMEIDiffFunction"].smart_md5:
            return 1
        else:
            return 0
        
    def match_basic_block_by_smart_md5(self, bb_a, bb_b):
        if bb_a.ext["PAIMEIDiffBasicBlock"].smart_md5 == bb_b.ext["PAIMEIDiffBasicBlock"].smart_md5:
            return 1
        else:
            return 0    
        
    def diff_function_by_smart_md5(self, function_a, function_b):
        if function_a.ext["PAIMEIDiffFunction"].smart_md5 != function_b.ext["PAIMEIDiffFunction"].smart_md5:
            return 1
        else:
            return 0
        
