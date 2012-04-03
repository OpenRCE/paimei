#!c:\python\python.exe

#
# FuzzIE - Internet Explorer CSS Fuzzing Arbiter
#
# $Id: fuzzie.py 218 2007-08-29 16:47:56Z pedram $
#
# REFERENCES:
#
#   - http://msdn.microsoft.com/workshop/browser/webbrowser/reference/objects/internetexplorer.asp
#   - http://bakemono/mediawiki/index.php/Internet_Explorer_Object_Model
#

import os
import time
import thread
from win32com.client import Dispatch

from pydbg import *
from pydbg.defines import *

kernel32        = windll.kernel32
user32          = windll.user32
CLSID           = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
SW_SHOW         = 5

test_number     = 1            # global test number.
crash_number    = 1            # global crash count.
crash_wait_time = 2            # seconds to wait for a crash before moving to next test case.
path            = "fuzzie"     # path to fuzzie directory (assumes c:\).
ie_ok           = True         # global.

########################################################################################################################

def access_violation_handler (debugger, dbg, context):
    global test_number
    global crash_number
    global ie_ok

    print
    print "test case #%d caused access violation #%d" % (test_number, crash_number)
    print

    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    # disassemble the instruction the exception occured at.
    disasm = debugger.disasm(exception_address)

    crash_log = open("bin-%d\\crash.log" % crash_number, "w+")

    crash_log.write("ACCESS VIOLATION @%08x: %s\n" % (exception_address, disasm))

    if write_violation:
        crash_log.write("violation when attempting to write to %08x\n" % violation_address)
    else:
        crash_log.write("violation when attempting to read from %08x\n" % violation_address)

    mbi = debugger.virtual_query(violation_address)

    crash_log.write("page permissions of violation address: %08x\n" % mbi.Protect)
    crash_log.write("\n")
    crash_log.write(debugger.dump_context(context))
    crash_log.write("\n")
    crash_log.write("call stack at time of crash:\n")

    for address in debugger.stack_unwind():
        crash_log.write("%08x\n" % address)

    crash_log.write("\n")
    crash_log.write("SEH chain at time of crash:\n")

    for address in debugger.seh_unwind():
        crash_log.write("%08x\n" % address)

    crash_log.close()

    # kill this process.
    debugger.terminate_process()

    crash_number += 1

    # flag the main loop that IE has to be restarted.
    ie_ok = False

    return


def start_debugger (debugger, pid):
    debugger.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation_handler)
    debugger.attach(pid)
    debugger.debug_event_loop()

########################################################################################################################

while 1:
    # start up IE.
    kernel32.WinExec("c:\\program files\\internet explorer\\iexplore.exe http://bakemono", SW_SHOW)

    # give IE some time to start up.
    time.sleep(1)

    debugger = pydbg()

    for (pid, proc) in debugger.enumerate_processes():
        if proc.lower == "iexplore.exe":
            break

    # thread out debugger.
    thread.start_new_thread(start_debugger, (debugger, pid))

    # IE is healthy and running.
    ie_ok = True

    # ensure the appropriate bin directory exists.
    try:
        os.mkdir("bin-%d" % crash_number)
    except:
        1   # do nothing

    # grab a COM handle to the IE instance we spawned.
    start = int(time.time())
    for ie in Dispatch(CLSID):
        ie_pid = c_ulong()
        user32.GetWindowThreadProcessId(ie.HWND, byref(ie_pid))
        if ie_pid.value == pid:
            break
    print "dispatch took %d seconds.\r" % (int(time.time()) - start),

    # loop through test cases while IE is healthy, if it dies the main loop we restart it.
    while ie_ok:
        # generate a test case.
        start = int(time.time())
        os.system("c:\\ruby\\bin\\ruby.exe bnf_reader.rb > bin-%d\\%d.html" % (crash_number, test_number))
        print "test case gen #%d took %d seconds.\r" % (test_number, int(time.time()) - start),

        # make IE navigate to the generated test case.
        try:
            ie.Navigate("file:///c:/fuzzie/bin-%d/%d.html" % (crash_number, test_number))
        except:
            print
            print "no instance of IE found"
            ie_ok = False

        # give IE a window of opportunity to crash before moving on.
        time.sleep(crash_wait_time)

        # increment the test count
        test_number += 1

    print "IE is not ok ... restarting."
