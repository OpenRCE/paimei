from idaapi         import *
from idautils       import *
from idc            import *

from pida    import *
#import pida

import time

'''
Variable backtrace script for IDA.

This does not work independantly of IDA at the moment, but does however rely on the PIDA 
extensions for manipulating varivakes

$Id: var_backtrace.py 194 2007-04-05 15:31:53Z cameron $

'''

ida_log = lambda x: sys.stdout.write(x + "\n")

def extract_internal_registers(operand):
    '''
    Extracts any registers nested inside a reference.
    
    @type   operand:    String
    @param  operand:    The operand to inspect
    
    @rtype:     String List
    @returns:   A list of registers embedded in the given reference
    '''
    stripped = operand.lstrip('[').rstrip(']')
    components = stripped.replace('*', '+').split('+')
    ret_val = []
    for reg in components:
        if not (reg[-1] == "h" and reg.rstrip('h').isdigit()):
            ida_log("adding %s" % reg)
            ret_val.append(reg)
            
    return ret_val

def choose_backtrace_target(ea):
    '''
    Prompts the user for the target operand in the current instruction.
    TODO: allow user to manually enter a target if none are found
    
    @type   ea: DWORD
    @param  ea: The address to search for operands
    
    @rtype:     String
    @returns:   The text representation of the variable to backtrace
    '''
    targets = []
    
    for op_index in xrange(3):
        current_tgt = GetOpnd(ea, op_index)
        if (current_tgt != None and current_tgt != "" and not (current_tgt in targets)):
            targets.append(current_tgt)
            if current_tgt.find('dword ptr [') == 0:
                targets.append(current_tgt.lstrip('dword ptr '))
                targets += extract_internal_registers(current_tgt.lstrip('dword ptr '))
            elif current_tgt[0] == '[' and current_tgt[-1] == ']':
                targets += extract_internal_registers(current_tgt)      
            
    for target in targets:                
        prompt_result = AskYN(1, "Backtrace %s?" % target)
        if prompt_result == -1:
            return None
        elif prompt_result == 1:
            return target
            
    return None
    
def trace_block(heads, initial_target, initial_ea=None):
    '''
    Traces backwards through a basic block looking for adjustments to the 
    target variable.
    
    @type   initial_target: String
    @param  initial_target: The value of the current variable being traced
    
    @type   initial_ea:     DWORD
    @param  initial_ea:     The initial address to begin the trace from. If empty, it will start at the end of the block.
    
    @rtype:     tuple(String,String,DWORD)    
    @returns:   a Tuple consisting of the new target, the type of source if any and the address if a source is found.
    '''
    heads.reverse()    
    target = [initial_target]
    if target[0][0] == '[':
        target.append(extract_internal_registers(target[0])[0]) # only look for the base
    
    # if len(target) > 1:
    #    ida_log("also %s" % target[1])
    
    if initial_ea == None:
        initial_ea = heads[0].ea
    
    ida_log("%08x: starting block trace. %d instructions." % (heads[0].ea, len(heads)))
    
    mod_type = None
    mod_addr = None
    
    for ins in heads:  # Go from the end
        if ins.ea > initial_ea:
            pass
        elif ("eax" in target) and (ins.mnem == "call") and ins.ea != initial_ea:
                # trace into call                
                mod_type = "call"
                mod_addr = ins.ea
                target = None
                break            
                
        elif (ins.mnem == "mov") and (ins.op1 in target):
            target = [ins.op2]            
            if target[0][0] == '[':
                target.append(extract_internal_registers(target[0])[0]) # only look for the base            
            ida_log("%08x: Switched trace to %s" % (ins.ea, target[0]))           
        elif (ins.mnem == "lea") and (ins.op1 in target):
            target = [ins.op2]
            if target[0][0] == '[':
                target.append(extract_internal_registers(target[0])[0]) # only look for the base
            ida_log("%08x: Switched trace to %s" % (ins.ea, target[0]))           
        elif (ins.mnem == "xor") and (ins.op1 in target) and (ins.op2 in target):
            mod_type = "zero"
            mod_addr = ins.ea
            target = None
            break 
        elif (ins.mnem == "pop") and (ins.op1 in target):
            mod_type = "pop"
            mod_addr = ins.ea
            target = None
            break        
            
    if target != None:
        target = target[0]            
        
    return (target, mod_type, mod_addr)
    
    
target = choose_backtrace_target(ScreenEA())

if target == None:
    ida_log("No target chosen")
else:
    ida_log("Target \"%s\" chosen for backtrace" % target)

current_ea = ScreenEA()
    
fn = function(current_ea)
 
bb = fn.find_basic_block(current_ea)
 
target,mod,addr = trace_block(bb.sorted_instructions(), target, current_ea)
kill_count = 0

var_src = {}

if target == None:
    var_src[addr] = mod
else:
    bb_hits = {}    
    bb_targets = {}
    
    new_travel = [bb.function.nodes[edge.src] for edge in bb.function.edges_to(bb.id)]
           
    if (new_travel == None) or (len(new_travel) == 0):
        ida_log("%08x: No blocks found." % bb.start_ea)
    else:
        for block in new_travel:
            ida_log("Adding source: %08x" % block.ea_start)
            bb_targets[block] = target
    
    while len(bb_targets) > 0:
        bb = bb_targets.keys()[0]        
        target = bb_targets[bb]
        del bb_targets[bb]
        
        if not bb.ea_start in bb_hits:
            target,mod,addr = trace_block(bb.sorted_instructions(), target) 
            
            bb_hits[bb.ea_start] = target  
            
            new_travel = [bb.function.nodes[edge.src] for edge in bb.function.edges_to(bb.id)]
           
            if mod != None:
                var_src[addr] = mod
            elif (new_travel == None) or (len(new_travel) == 0):
                if (bb.ea_start == bb.function.ea_start):
                    var_src[bb.ea_start] = "fn_arg:" + target
                else:
                    ida_log("%08x: No blocks found." % bb.ea_start)
            else:
                for block in new_travel:
                    bb_targets[block] = target
            
            
            # kill_count += 1
            if kill_count == 20:
                ida_log("Hit kill count")
                break
                
ida_log("Possible sources detected: %d" % len(var_src))
for key in var_src.keys():
    if var_src[key] == "zero":
        ida_log("%08x: Memory Zeroed" % key)
    elif var_src[key] == "call":
        ida_log("%08x: Return value from CALL" % key)
    elif var_src[key].find("fn_arg") == 0:
        ida_log("%08x: Passed in to the function via %s" % (key ,var_src[key].lstrip("fn_arg:")))
        xrefs = CodeRefsTo(key, 0)
        ida_log("found %d xrefs" % len(xrefs))