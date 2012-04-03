#!c:\python\python.exe

# $Id: demo_live_graphing.py 194 2007-04-05 15:31:53Z cameron $

import thread
import sys
import time

import pida
import pgraph
import utils

from pydbg import *
from pydbg.defines import *


# globals
udraw       = None
first_graph = True
vonage      = None
last_graph  = None
last_center = None

########################################################################################################################

def udraw_node_double_click (udraw, args):
    print "udraw_node_double_click"
    print args

########################################################################################################################

def breakpoint_handler (pydbg):
    global udraw, first_graph, vonage, last_graph, last_center

    if pydbg.first_breakpoint:
        return DBG_CONTINUE

    exception_address = pydbg.exception_address
    
    if first_graph:
        print "drawing graph"
        first_graph = False
        
        last_graph = vonage.graph_proximity(exception_address, 0, 1)
        udraw.graph_new(last_graph)
        #udraw.change_element_color("node", exception_address, 0xFF8000)
        #last_center = exception_address
    else:
        print "updating graph"
        proximity = vonage.graph_proximity(exception_address, 0, 1)
        proximity.graph_sub(last_graph)
        last_graph.graph_cat(proximity)
        udraw.graph_update(proximity)
        #udraw.change_element_color("node", last_center, 0xEEF7FF)
        #udraw.change_element_color("node", exception_address, 0xFF8000)

    # remove the breakpoint once we've hit it.
    pydbg.bp_del(exception_address)

    return DBG_CONTINUE

########################################################################################################################

udraw = utils.udraw_connector()
udraw.set_command_handler("node_double_click", udraw_node_double_click)

# thread out the udraw connector message loop.
thread.start_new_thread(udraw.message_loop, (None, None))

start = time.time()
print "loading vonage.exe.pida ...",
vonage = pida.load("vonage.exe.pida")
print "done. completed in %.02f seconds." % (time.time() - start)

dbg = pydbg()
dbg.set_callback(EXCEPTION_BREAKPOINT, breakpoint_handler)
for (pid, proc) in dbg.enumerate_processes():
    if proc.lower().startswith("x-pro-vonage"):
        break

if not proc.lower().startswith("x-pro-vonage"):
    print "vonage not found"
    sys.exit(1)

dbg.attach(pid)

bps = [function.ea_start for function in vonage.nodes.values() if not function.is_import]
print "setting breakpoints on %d of %d functions" % (len(bps), len(vonage.nodes.values()))
dbg.bp_set(bps, restore=False)

dbg.debug_event_loop()