#
# $Id: stack_frame.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class stack_frame:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 1             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Stack_Frame"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Stack Frame module uses the functions stack frame as a signature"
        self.date        = "09/22/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_LOW        
        
        self.parent.register_match_function(    self.match_function_by_stack_frame,    self )   # register a function matching routine
        self.parent.register_diff_function(     self.diff_function_by_stack_frame,     self )   # register a function diffing routine
        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_stack_frame(self, function_a, function_b):
        if function_a.frame_size == function_b.frame_size:
            return 1
        else:
            return 0
        
    def diff_function_by_stack_frame(self, function_a, function_b):
        if function_a.frame_size != function_b.frame_size:
            return 1
        else:
            return 0
            