#
# $Id: name.py 194 2007-04-05 15:31:53Z cameron $
#

from defines import *

class name:
    def __init__(self, parent=None):
        self.attributes = {}                    # initialize attributes
        
        self.attributes["Match"] = 1            # Match attribute set to 1 tells the main program we can be used to match 
        self.attributes["Diff"] = 0             # Diff  attribute set to 1 tells the main program we can be used to diff
        self.attributes["Level"] = FUNCTION_LEVEL # these flags indicated we can diff/match both functions and basic blocks
        self.parent = parent                    # set up the parent
        
        self.module_name = "Name"                # give the module a name
        self.author      = "Peter Silberman"    # author name
        self.description = "Name module matches using symbols"
        self.date        = "09/15/06"
        self.homepage    = "http://www.openrce.org"
        self.contact     = "peter.silberman@gmail.com"
        self.accuracy    = ACCURACY_HIGH
        
        self.parent.register_match_function(    self.match_function_by_name,    self )   # register a function matching routine
        self.parent.register_module(self)                                               # register our module in the module table
        
    def match_function_by_name(self, function_a, function_b):
#        fd = open("name.out", "a+")
#        fd.write("%s %s\n" % (function_a.name, function_b.name))
        if function_a.name.lower() == function_b.name.lower():
#            fd.write("\t\tMatched\n\n")
#            fd.close()
            return 1
        else:
#            fd.write("\n\n")
#            fd.close()
            return 0
        
