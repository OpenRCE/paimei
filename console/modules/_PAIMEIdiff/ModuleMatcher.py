#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: ModuleMatcher.py 194 2007-04-05 15:31:53Z cameron $
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

import time
import wx

import pida

class ModuleMatcher:
    def __init__(self, parent, mod_a, mod_b):
        self.parent = parent
        self.mod_a = mod_a # module a
        self.mod_b = mod_b # module b
        (self.ignore_num_nodes, self.ignore_num_edges, self.ignore_num_calls, self.ignore_num_instructions) = self.parent.insignificant_function
        self.ignore_bb = self.parent.insignificant_bb
        self.proximity_start = 0
    
    ####################################################################################################################        
    def prune_insig(self):
        '''
        remove the insignificant functions from the listing
        '''
        i = 0
        remove_count = 0
        
        while i < len(self.mod_a.nodes):
            if self.mod_a.nodes.values()[i].is_import:
                del self.mod_a.nodes[ self.mod_a.nodes.keys()[i] ]
                remove_count+=1
            elif self.is_function_insignificant(self.mod_a.nodes.values()[i]):
                del self.mod_a.nodes[ self.mod_a.nodes.keys()[i] ]
                remove_count+=1
            else:
                i+=1
        self.parent.msg("Removed %d insignificant functions from module a" % remove_count)
        
        i = 0
        remove_count = 0
        while i < len(self.mod_b.nodes):
            if self.mod_b.nodes.values()[i].is_import:
                del self.mod_b.nodes[ self.mod_b.nodes.keys()[i] ]
                remove_count+=1
            elif self.is_function_insignificant(self.mod_b.nodes.values()[i]):
                del self.mod_b.nodes[ self.mod_b.nodes.keys()[i] ]
                remove_count+=1
            else:
                i+=1        
        self.parent.msg("Removed %d insignificant functions from module b" % remove_count)
        
    ####################################################################################################################        
    def is_function_insignificant(self, function):
        if function.ext["PAIMEIDiffFunction"].num_calls <= self.ignore_num_calls and function.num_instructions <= self.ignore_num_instructions and len(function.nodes.values()) <= self.ignore_num_nodes:
            return 1
        else:
            return 0           
            
    ####################################################################################################################
    def match_modules(self):
        self.parent.msg("Before removing functions in a: %d" % len(self.mod_a.nodes))
        self.parent.msg("Before removing functions in b: %d" % len(self.mod_b.nodes))
        self.prune_insig()
        self.parent.msg("After removing functions in a: %d" % len(self.mod_a.nodes))
        self.parent.msg("After removing functions in b: %d" % len(self.mod_b.nodes))
        busy = wx.BusyInfo("matching modules...stand by.")
        wx.Yield()
        start = time.time()
        self.match_by_functions()
        
        self.parent.msg("matched %d function(s) in %.2f seconds." % (self.parent.matched_list.num_matched_functions, round(time.time() - start, 3) ) ) 
        busy = wx.BusyInfo("matching basic blocks...stand by.")
        wx.Yield()
        start = time.time()
        self.match_basic_block()
        self.parent.msg("matched %d basic block(s) and ignored %d basic block(s) in %.2f seconds." % (self.parent.matched_list.num_matched_basic_block, self.parent.matched_list.num_ignored_basic_block, round(time.time() - start, 3) ) ) 
        i = 0
        while i < len(self.mod_a.nodes.values()):
            self.parent.unmatched_list.add_to_unmatched_a(self.mod_a.nodes.values()[i])
            i+=1
        i = 0
        while i < len(self.mod_b.nodes.values()):
            self.parent.unmatched_list.add_to_unmatched_b(self.mod_b.nodes.values()[i])
            i+=1

    ####################################################################################################################
    def match_by_functions(self):
        curr_change = 0 # will keep track of the changes that have been found during the current iteration
        prev_change = 1 # will store the previous number of changes that occured in the last iteration
        match_num = found = dup = 0 # flags
        a = b = 0 # counter
        saved_a = saved_b = 0
        # while there is still a change
        
        num_functions = len(self.parent.used_match_function_table)
        match_functions = sorted(self.parent.used_match_function_table.keys())
        
        
        while prev_change != curr_change:
 #           print "Func: %d %d" % (prev_change, curr_change)
            i = 0               # reset counter
            prev_change = curr_change
            curr_change = 0     # reset counter
            
            # loop through all the algorithms
            while i < num_functions:
                    self.parent.msg("Method: %s" % match_functions[i][1:])
                    b = 0
                    # get the name of the algorithm
                    name = match_functions[i]
                    
                    # for all the functions in module b
                    while b < len(self.mod_b.nodes.values()):
                        a = 0            
                        
                        #for all the functions in module b
                        while a < len(self.mod_a.nodes.values()):
                            # match function_a to function_b 
                            if self.parent.used_match_function_table[ name ](self.mod_a.nodes.values()[a], self.mod_b.nodes.values()[b]):
                                # if we found a match to function b using function a then we save the state
                                if not dup:
                                    found = 1
                                    saved_a = a
                                    saved_b = b
                                    func_a = self.mod_a.nodes.values()[a]
                                    func_b = self.mod_b.nodes.values()[b]
                                    if self.parent.module_table[name [1:]].accuracy == 0x003:
                                        break
                                else:
                                    # if we have already found a match to function b and we find a second one
                                    # then we need to set the dup flag to indicate this iteration is invalid
                                    dup = 1 
                                    break
                            a+=1
                        
                        # if we found a match and there was no duplicated match then mark the functions as matched
                        if found and not dup:
                            curr_change+=1
                            # add functions to matched list
                            self.parent.matched_list.add_matched_function(func_a, func_b, name[1:])
                            key = self.mod_a.nodes.keys()[saved_a]
                            del self.mod_a.nodes[ key ]
                            key = self.mod_b.nodes.keys()[saved_b]
                            del self.mod_b.nodes[ key ]
                        else:
                            # we only add one to b if we did not find a match 
                            b+=1
                        found = dup = 0
                    
                    # after one complete iteration over all functions we call the proximity function                        
                    curr_change += self.match_function_by_proximity()
                    i+=1

    
    ####################################################################################################################
    def match_basic_block(self):
        
        i = idx = 0
        a = b =0
        dup = found = 0
        saved_a = saved_b = 0
        total_bb = 0
        prev_change = 1
        curr_change = 0
        
        #num_bb_matched = 0 
        #num_bb_a_ignored = 0
        #num_bb_b_ignored = 0
        
        match_basic_block_funcs = sorted(self.parent.used_match_basic_block_table.keys())
        num_functions = len(self.parent.used_match_basic_block_table)
        num_matched_functions =  len(self.parent.matched_list.matched_functions)
        
        while prev_change != curr_change:
            prev_change = curr_change
#            print "BB: %d %d" % (prev_change, curr_change)
            curr_change = 0
            idx = 0
            # for every pair of matched functions
            while idx < num_matched_functions:
                # get the functions
                (func_a, func_b) = self.parent.matched_list.matched_functions[idx]
                
                func_b_sorted_nodes = func_b.sorted_nodes()
                func_a_sorted_nodes = func_a.sorted_nodes()

                len_a = len(func_a_sorted_nodes)
                len_b = len(func_b_sorted_nodes)
                     
                #self.parent.msg("Matching basic blocks for %s:%d and %s:%d" % (func_a.name,len_a, func_b.name, len_b)) 
                
                
                #num_bb_matched = 0
                #num_bb_a_ignored = 0
                #num_bb_b_ignored = 0
                i = 0
                # loop through every basic block algorithm
                while i < num_functions:
                    if func_b.ext["PAIMEIDiffFunction"].num_bb_id == len_b or func_a.ext["PAIMEIDiffFunction"].num_bb_id == len_a:
                        break
                    # tell the user what method we are applying to the basic blocks
                    #self.parent.msg("BB Method: %s" % sorted(self.parent.used_match_basic_block_table.keys())[i][1:]) 
                    b = 0                            
                    # for all the basic blocks in function b
                    while b < len_b:
                        #print "B: %d" % b
                        if func_b.ext["PAIMEIDiffFunction"].num_bb_id == len_b:
                            break
                        a = 0

                        if func_b_sorted_nodes[b].ext["PAIMEIDiffBasicBlock"].ignore or func_b_sorted_nodes[b].ext["PAIMEIDiffBasicBlock"].matched:
                            b+=1
                            continue
                        elif func_b_sorted_nodes[b].num_instructions <= self.ignore_bb:
                            self.parent.matched_list.mark_basic_block_ignored(idx, -1, b)
                            b+=1
                            continue
                        elif func_b.ext["PAIMEIDiffFunction"].num_bb_id == len_b:
                            b+=1
                            break
                            
                        # for all basic blocks in function a                        
                        while a < len_a:
                            #print "A: %d" % a
                            if func_a.ext["PAIMEIDiffFunction"].num_bb_id == len_a:
                                break
                            #(func_a, func_b) = self.parent.matched_list.matched_functions[idx]
                            if func_a_sorted_nodes[a].ext["PAIMEIDiffBasicBlock"].ignore or func_a_sorted_nodes[a].ext["PAIMEIDiffBasicBlock"].matched:
                                a+=1
                                continue
                            elif func_a_sorted_nodes[a].num_instructions <= self.ignore_bb:
                                self.parent.matched_list.mark_basic_block_ignored(idx, a, -1)
                                a+=1
                                continue
                            elif func_a.ext["PAIMEIDiffFunction"].num_bb_id == len_a:
                                a+=1
                                break
                            
                            # call the basic block matching algorithm                                 
#                            if self.parent.used_match_basic_block_table[ sorted(self.parent.used_match_basic_block_table.keys())[i]](func_a.sorted_nodes()[a], func_b.sorted_nodes()[b]):
                            
                            if self.parent.used_match_basic_block_table[ match_basic_block_funcs[i] ](func_a_sorted_nodes[a], func_b_sorted_nodes[b]):
                                
                                # if there are no dups save state
                                if not dup:
                                    found = 1
                                    saved_a = a
                                    saved_b = b
                                else:
                                    # a previous match was found indicate there is a duplication
                                    dup = 1
                                    break
                            a+=1         
                        
                        # if a match was found and there was no duplication                                                           
                        if found and not dup:
                            #num_bb_matched += 1
                            curr_change += 1
                            # mark the basic block as matched
                            self.parent.matched_list.mark_basic_block_matched(idx, saved_a, saved_b, match_basic_block_funcs[i][1:] )
                            
                        found = dup = 0    
                        b+=1
                    #print "%s: a(%d + %d) == %d and %s: b(%d + %d) == %d" % (func_a.name, num_bb_a_ignored, num_bb_matched, len(func_a.sorted_nodes()), func_b.name, num_bb_b_ignored, num_bb_matched, len(func_b.sorted_nodes()))                                     
                    #self.parent.msg("Exiting i") 
                    i+=1           
                    #return
                    
                #self.parent.msg("Exiting idx") 
                idx+=1            
                #return
        
    ####################################################################################################################
    def is_basic_block_insignificant(self, func, i):
        if func.sorted_nodes()[i].ext["PAIMEIDiffBasicBlock"].ignore or func.sorted_nodes()[i].ext["PAIMEIDiffBasicBlock"].matched:
            return 1
            
        if func.sorted_nodes()[i].num_instructions <= self.ignore_bb:
            return 2

        if func.ext["PAIMEIDiffFunction"].num_bb_id == len(func.sorted_nodes()):
            return 3
        return 0
    
    ####################################################################################################################
    def match_function_by_proximity(self):
        '''
        take all matched functions and scan for calls within the functions, if we find a call to a function within the module
        we check to make sure function_b has the same call and then we take both functions that are called and considered them
        matched.

        @author: Peter Silberman
        '''
        
        matched_count = 0
        a = 0
        inst_list_a = []
        i = self.proximity_start
        #print "Entering proximity %d" % len(self.matched_functions)
        while i < len(self.parent.matched_list.matched_functions):
            function_a, function_b = self.parent.matched_list.matched_functions[i]
            #there are not same number of basic blocks ignore the function
            if len(function_a.nodes) != len(function_b.nodes):
                i+=1
                continue
            a = 0
            while a < len(function_a.nodes):
                inst_list_a = function_a.sorted_nodes()[a].sorted_instructions()
                if len(function_b.sorted_nodes()[a].sorted_instructions()) != len(inst_list_a):
                    break
                #print "Checking %s" % function_a.name
                inst_list_b = function_b.sorted_nodes()[a].sorted_instructions()
                for index_a,inst_a in enumerate(inst_list_a):
                    if inst_a.mnem == "call" and inst_a.refs_api == None:
                        #print "Found a call in %s at index %d" % (function_a.name, index_a)
                        proximity_from_entry = inst_a.ext["PAIMEIDiffInstruction"].distance_entry
                        proximity_from_exit  = inst_a.ext["PAIMEIDiffInstruction"].distance_exit
                        #print "Entry: %d Exit: %d index: %d" % (proximity_from_entry,proximity_from_exit, index_a)
                        #print "==> Entry: %d Exit: %d mnem: %s" % (inst_list_b[index_a].ext["PAIMEIDiffInstruction"].distance_entry, inst_list_b[index_a].ext["PAIMEIDiffInstruction"].distance_exit, inst_list_b[index_a].mnem)
                        #if inst_list_b[index_a].ext["PAIMEIDiffInstruction"].distance_entry == proximity_from_entry:
                        if inst_list_b[index_a].mnem == "call" and inst_list_b[index_a].refs_api == None:
                            new_function_a,key_a = self.get_function(self.mod_a, inst_a.op1)
                            #print "Looking for %s" % inst_a.op1
                            new_function_b,key_b = self.get_function(self.mod_b, inst_list_b[index_a].op1)
                            #print "Looking for %s" % inst_list_b[index_a].op1
                            if new_function_b != None and new_function_a != None:
                                self.parent.matched_list.matched_functions[i] = (function_a, function_b)
                                self.parent.matched_list.add_matched_function(new_function_a, new_function_b, "Proximity")
                                matched_count += 1
                                del self.mod_a.nodes[key_a]
                                del self.mod_b.nodes[key_b]
                            else:
                                break
                a+=1
            i+=1
        self.proximity_start += (i - self.proximity_start) 
        return matched_count
        
    ####################################################################################################################
    def get_function(self, module, function_name):
        '''
        get an instance of the function class given the function name and the module

        @author: Peter Silberman

        @type   module:  module
        @param  module:  module
        @type   function_name:  string
        @param  function_name:  the name of the function to get

        @rtype: tuple
        @return: None, or the function_a, and the index
        '''
        i = 0
        while i < len(module.nodes.values()):
            if module.nodes.values()[i].name == function_name:
                return (module.nodes.values()[i], module.nodes.keys()[i])
            i+=1
        return (None,None)
        
    