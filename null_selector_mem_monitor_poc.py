#!c:\\python\\python.exe

"""
Null Selector Mem-Monitor Proof of Concept
Copyright (C) 2007 Pedram Amini <pedram.amini@gmail.com>

$Id: null_selector_mem_monitor_poc.py 214 2007-08-23 05:48:44Z pedram $

Description:
    Pydbg implementation of skape's null selector mem-monitor technique:

        http://www.uninformed.org/?v=7&a=1

    I forget how functional this is, or if it even really works.

TODO (performance improvements):
    - intelligently skip over REP sequences
"""

from pydbg import *
from pydbg.defines import *

def evaluate_expression (dbg):
    expression = dbg.disasm(dbg.exception_address)

    for reg in ["eax", "ebx", "ecx", "edx", "ebp", "esi", "edi"]:
        expression = expression.replace(reg, "%d" % dbg.get_register(reg))

    return eval(expression[expression.index('[')+1:expression.index(']')])

def set_selectors(dbg, val, thread_id=None):
    if thread_id:
        thread_ids = [thread_id]
    else:
        thread_ids = dbg.enumerate_threads()

    for tid in thread_ids:
        handle  = dbg.open_thread(tid)
        context = dbg.get_thread_context(handle)
        context.SegDs = val
        context.SegEs = val
        dbg.set_thread_context(context, handle)
        dbg.close_handle(handle)

def entry_point (dbg):
    print "%08x: %s" % (dbg.exception_address, dbg.disasm(dbg.exception_address))
    print "%08x" % dbg.context.SegDs
    set_selectors(dbg, 0)
    return DBG_CONTINUE

def av_handler (dbg):
    if dbg.write_violation:
        direction = "write to"
    else:
        direction = "read from"

    #print "AV: %08x via %s %08x" % (dbg.exception_address, direction, evaluate_expression(dbg))
    #print dbg.dump_context()

    set_selectors(dbg, 0x23, dbg.dbg.dwThreadId)

    if dbg.mnemonic.startswith("rep"):
        dbg.bp_set(dbg.exception_address + dbg.instruction.length, handler=nullify_selectors)
    else:
        dbg.single_step(True)

    return DBG_CONTINUE

def nullify_selectors (dbg):
    set_selectors(dbg, 0, dbg.dbg.dwThreadId)
    return DBG_CONTINUE

def thread_handler (dbg):
    set_selectors(dbg, 0, dbg.dbg.dwThreadId)
    return DBG_CONTINUE

dbg = pydbg()
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
dbg.set_callback(EXCEPTION_SINGLE_STEP,      nullify_selectors)
dbg.set_callback(CREATE_THREAD_DEBUG_EVENT,  thread_handler)

dbg.load(r"c:\windows\system32\calc.exe")
dbg.bp_set(0x01012475, handler=entry_point)

dbg.run()
