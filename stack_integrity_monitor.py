#!c:\python\python.exe

"""
Stack Integrity Monitor
Copyright (C) 2007 Pedram Amini <pedram.amini@gmail.com>

$Id: stack_integrity_monitor.py 214 2007-08-23 05:48:44Z pedram $

Description:
    A command line utility implemented in under 150 lines of Python code which provides an automated solution to the
    task of tracking down the source of a stack overflow. The main reason stack overflows are exploitable is because
    control information is stored in the same medium as volatile user-controllable data. If we can move or mirror the
    call-chain "out of band", then we can verify the integrity of the stack at run-time. Skipping over the intricate
    details, here is the high level overview of how the utility works:

        1. Instantiate a debugger object and attach to the target program.
        2. Set a breakpoint where we want the trace to start, this can be as simple as setting a break on recv().
        3. Once the breakpoint is hit, set the active thread to single step.
        4. When a CALL instruction is reached, copy the stack and return addresses to an internal "mirror" list.
        5. When a RET instruction is reached, walk through the "mirror" list and verify that the values match the
           actual stack.
        6. When the last saved return address is reached, pop it off the internal "mirror" list.

    If during the stack integrity check a mismatch is found, then not only do we know that a stack overflow has
    occurred, but we know which functions frame the overflow originated in and we can pinpoint the cause of the
    overflow. For more information see:

        http://dvlabs.tippingpoint.com/blog/2007/05/02/pin-pointing-stack-smashes

TODO (performance improvements):
    - replace disasm with byte checks
    - step over rep sequences
"""

import sys
import time
import utils
import pydbgc

from pydbg         import *
from pydbg.defines import *


USAGE = "USAGE: stack_fuck_finder.py <BP ADDR> <PID>"
error = lambda msg: sys.stderr.write("ERROR> " + msg + "\n") or sys.exit(1)


########################################################################################################################
def check_stack_integrity (dbg):
    if not dbg.juju_found:
        for addr, value in dbg.mirror_stack:
            new_value = dbg.flip_endian_dword(dbg.read(addr, 4))

            if new_value != value:
                dbg.juju_found = True

                for a, v in dbg.mirror_stack:
                    if a == addr:
                        print "%08x: %s.%08x --> %08x" % (a, dbg.addr_to_module(v).szModule, v, new_value)
                    else:
                        print "%08x: %s.%08x" % (a, dbg.addr_to_module(v).szModule, v)

                print
                print "STACK INTEGRITY VIOLATON AT: %s.%08x" % (dbg.addr_to_module(dbg.context.Eip).szModule, dbg.context.Eip)
                print "analysis took %d seconds" % (time.time() - dbg.start_time)
                print

                d = pydbgc.PydbgClient(dbg, False)
                d.command_line()

                break


########################################################################################################################
def handler_trace_start (dbg):
    dbg.monitor_tid = dbg.dbg.dwThreadId
    print "starting hit trace on thread %d at 0x%08x" % (dbg.monitor_tid, dbg.context.Eip)
    dbg.single_step(True)

    return DBG_CONTINUE


########################################################################################################################
def handler_breakpoint (dbg):
    if dbg.first_breakpoint:
        return DBG_CONTINUE

    # ignore threads we don't care about that happened to hit one of our breakpoints.
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        return DBG_CONTINUE

    if dbg.mirror_stack:
        dbg.mirror_stack.pop()

    dbg.single_step(True)
    return DBG_CONTINUE


########################################################################################################################
def handler_single_step (dbg):
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        return DBG_CONTINUE

    if dbg.juju_found:
        return DBG_CONTINUE

    disasm   = dbg.disasm(dbg.context.Eip)
    ret_addr = dbg.get_arg(0)

    # if the current instruction is in a system DLL and the return address is not, set a breakpoint on it and continue
    # without single stepping.
    if dbg.context.Eip > 0x70000000 and ret_addr < 0x70000000:
        dbg.bp_set(ret_addr)
        return DBG_CONTINUE

    #print "%08x: %s" % (dbg.context.Eip, dbg.disasm(dbg.context.Eip))

    if dbg.mirror_stack and dbg.context.Eip == dbg.mirror_stack[-1][1]:
        dbg.mirror_stack.pop()

    if disasm.startswith("ret"):
        check_stack_integrity(dbg)

    if disasm.startswith("call"):
        dbg.mirror_stack.append((dbg.context.Esp-4, dbg.context.Eip + dbg.instruction.length))

    dbg.single_step(True)
    return DBG_CONTINUE


########################################################################################################################
def handler_access_violation (dbg):
    check_stack_integrity(dbg)

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)

    print crash_bin.crash_synopsis()
    dbg.terminate_process()


########################################################################################################################
if len(sys.argv) != 3:
    error(USAGE)

try:
    bp_addr = long(sys.argv[1], 16)
    pid     = int(sys.argv[2])
except:
    error(USAGE)

dbg = pydbg()
dbg.mirror_stack = []
dbg.monitor_tid  = 0
dbg.start_time   = time.time()
dbg.juju_found   = False

dbg.set_callback(EXCEPTION_BREAKPOINT,       handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP,      handler_single_step)
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

dbg.attach(pid)
dbg.bp_set(bp_addr, handler=handler_trace_start, restore=False)
print "watching for hit at %08x" % bp_addr
dbg.run()
