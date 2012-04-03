#!c:\\python\\python.exe

"""
PyDbg Just-In-Time Debugger
Copyright (C) 2007 Pedram Amini <pedram.amini@gmail.com>

$Id: just_in_time_debugger.py 213 2007-08-22 23:31:42Z pedram $

To install:
    Create a registry string value named "Debugger" with the following value:
    
        "c:\python\python.exe" "c:\vmfarm\shared\paimei\jit_test.py" %ld %ld

    Under the following key:
        
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
"""

import sys
import utils

from pydbg         import *
from pydbg.defines import *

# globals.
pid     = int(sys.argv[1])
h_event = int(sys.argv[2])
proc    = None
log     = r"c:\pydbg_jit.txt"

# skip the OS supplied breakpoint event and set the offending event to the signaled state.
def bp_handler (dbg):
    global h_event

    windll.kernel32.SetEvent(h_event)
    return DBG_CONTINUE

# print the crashing PID, proc name, crash synopsis and module list to disk.
def av_handler (dbg):
    global pid, proc, log

    fh = open(log, "a+")
    fh.write("\n" + "-"*80 + "\n")
    fh.write("PyDbg caught access violation in PID: %d, PROC: %s\n" % (pid, proc))

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)

    fh.write(crash_bin.crash_synopsis())

    fh.write("MODULE ENUMERATION\n")
    for name, base in dbg.enumerate_modules():
        fh.write("\t %08x: %s\n" % (base, name))

    fh.close()
    dbg.terminate_process()
    return DBG_CONTINUE

# hello pydbg.
dbg = pydbg()

# determine the process name by matching the violating PID.
for epid, eproc in dbg.enumerate_processes():
    if epid == pid:
        proc = eproc
        break

# register a breakpoint handler to skip the OS supplied breakpoint and register an AV handler to catch the exception.
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
dbg.set_callback(EXCEPTION_BREAKPOINT,       bp_handler)
dbg.attach(pid)
dbg.run()
