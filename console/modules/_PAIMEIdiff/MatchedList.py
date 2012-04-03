# $Id: MatchedList.py 194 2007-04-05 15:31:53Z cameron $





class MatchedList:
    '''
    Instantiated from PAIMEIdiff, this is the class that will keep track of all the matched functions, and perform
    all the utility functions like unmatching matching marking as matched etc.
    '''
    def __init__(self, parent=None):
        self.matched_functions      = []    # a list of tuples containing (function_a, function_b) that have been matched
        self.num_matched_functions  = 0     # number of functions matched
        self.num_ignored_functions  = 0     # number of ignored functions
        self.num_matched_basic_block = 0    # number of basic blocks matched
        self.num_ignored_basic_block = 0    # number of basic blocks ignored
        self.num_different_functions = 0    # number of different functions
        self.parent                 = parent

    ####################################################################################################################        
    def add_matched_function(self, function_a, function_b, matched_method):
        '''
        Add two functions to the matched list
        '''
        function_a.ext["PAIMEIDiffFunction"].matched            = function_b.ext["PAIMEIDiffFunction"].matched  = 1
        function_a.ext["PAIMEIDiffFunction"].match_method       = matched_method
        function_b.ext["PAIMEIDiffFunction"].match_method       = matched_method
        function_a.ext["PAIMEIDiffFunction"].matched_ea         = function_b.ea_start
        function_b.ext["PAIMEIDiffFunction"].matched_ea         = function_a.ea_start
        function_a.ext["PAIMEIDiffFunction"].matched_function   = function_b
        function_b.ext["PAIMEIDiffFunction"].matched_function   = function_a
        self.matched_functions.append( (function_a, function_b))
        self.num_matched_functions+=1
        
    ####################################################################################################################                                
    def mark_function_all_bb_matched(self, idx):
        (function_a, function_b) = self.matched_functions[idx]
        function_a.ext["PAIMEIDiffFunction"].all_bb_matched = function_b.ext["PAIMEIDiffFunction"].all_bb_matched = 1
        self.matched_functions[idx] = (function_a, function_b
        )                                     
    ####################################################################################################################
    def remove_matched_functions(self, i):
        '''
        Remove a set of functions from the matched list and return them
        '''
        matched = self.matched_functions.pop(i)
        return matched
        
    ####################################################################################################################
    def mark_basic_block_matched(self,i, bb_a_index, bb_b_index, match_method):
        '''
        Mark a basic block in each function as matched
        '''
        (function_a, function_b) = self.matched_functions[i]
        
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched       = function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched = 1
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].match_method  = match_method
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].match_method  = match_method
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched_ea    = function_b.sorted_nodes()[bb_b_index].ea_start
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched_ea    = function_a.sorted_nodes()[bb_a_index].ea_start
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched_bb    = function_b.sorted_nodes()[bb_b_index]
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched_bb    = function_a.sorted_nodes()[bb_a_index]
        
        function_a.ext["PAIMEIDiffFunction"].num_bb_id += 1
        function_b.ext["PAIMEIDiffFunction"].num_bb_id += 1
        
        
        self.matched_functions[i] = (function_a, function_b)
        self.num_matched_basic_block +=1

     
    ####################################################################################################################        
    def mark_basic_block_ignored(self, i, bb_a_index, bb_b_index):
        '''
        Mark a basic block in two functions as ignored
        ''' 
        (function_a, function_b) = self.matched_functions[i]   
        if bb_a_index != -1:
            function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].ignore = 1
            function_a.ext["PAIMEIDiffFunction"].num_bb_id += 1
            
        if bb_b_index != -1:
            function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].ignore = 1
            function_b.ext["PAIMEIDiffFunction"].num_bb_id += 1    
            
        self.matched_functions[i] = (function_a, function_b)
        self.num_ignored_basic_block+=1
    
    ####################################################################################################################    
    def mark_function_as_different(self, i):
        '''
        Mark two matched functions as different
        '''
        (function_a, function_b) = self.matched_functions[i]   
        function_a.ext["PAIMEIDiffFunction"].different = function_b.ext["PAIMEIDiffFunction"].different = 1   
        self.parent.msg("%s != %s" % (function_a.name, function_b.name))     
        self.matched_functions[i] = (function_a, function_b)
        self.num_different_functions+=1
    
    ####################################################################################################################        
    def unmark_function_as_different(self, i):
        '''
        Mark two matched functions as different
        '''
        (function_a, function_b) = self.matched_functions[i]   
        function_a.ext["PAIMEIDiffFunction"].different = function_b.ext["PAIMEIDiffFunction"].different = 0        
        self.matched_functions[i] = (function_a, function_b)
        self.num_different_functions-=1
    
    ####################################################################################################################
    def mark_basic_block_as_different(self, i, bb_a_index, bb_b_index):
        '''
        Mark a basic block that has been matched as different
        '''        
        (function_a, function_b) = self.matched_functions[i]   
        function_a.sorted_nodes()[bb_a_index]["PAIMEIDiffBasicBlock"].different = function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].different = 1        
        self.matched_functions[i] = (function_a, function_b)

    ####################################################################################################################
    def unmatch_basic_block(self, i, bb_a_index):
        '''
        Mark a previously matched basic block as unmatched
        '''
        (function_a, function_b) = self.matched_functions[i]
        
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched       = function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched = 0
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].match_method  = ""
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].match_method  = ""
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched_ea    = 0
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched_ea    = 0
        function_a.sorted_nodes()[bb_a_index].ext["PAIMEIDiffBasicBlock"].matched_bb    = None
        function_b.sorted_nodes()[bb_b_index].ext["PAIMEIDiffBasicBlock"].matched_bb    = None
        self.matched_functions[i] = (function_a, function_b)

    ####################################################################################################################
    def unmatch_function(self, i):
        '''
        Mark a previously matched set of functions as unmatched and remove them from the list
        '''
        (function_a, function_b) = self.matched_functions[i]
        function_a.ext["PAIMEIDiffFunction"].matched = function_b.ext["PAIMEIDiffFunction"].matched = 0
        function_a.ext["PAIMEIDiffFunction"].match_method = ""
        function_b.ext["PAIMEIDiffFunction"].match_method = ""
        function_a.ext["PAIMEIDiffFunction"].matched_ea   = 0
        function_b.ext["PAIMEIDiffFunction"].matched_ea   = 0
        function_a.ext["PAIMEIDiffFunction"].matched_function = None
        function_b.ext["PAIMEIDiffFunction"].matched_function = None
        del self.matched_functions[i]
        self.num_matched_functions-=1
        return (function_a, function_b)

