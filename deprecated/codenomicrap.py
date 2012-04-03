#!c:\python\python.exe

#
# Codenomicrap - Codenomicon Test Arbiter
#
# $Id: codenomicrap.py 218 2007-08-29 16:47:56Z pedram $
#

import time
import thread

from pydbg import *
from pydbg.defines import *

# pydbg server IP address and port.
pydbg_host = "10.0.0.1"
pydbg_port = 7373

# target start command.
target_start_command = "vmrun revertToSnapshot xxxx"

# target name. this is the string that will show up in process enumeration for pydbg to look for / attach to.
target_name = "RegSvr.exe"

# codenomicon command line. one format string token is supported to insert the test case number.
codenomicon_command_line = "java -jar sip231.jar --index %d- --to-uri sip:user@192.168.59.131 --from-uri sip:user@localhost --transport tcp"

########################################################################################################################
### SHOULD NOT NEED TO MODIFY BELOW THIS LINE
########################################################################################################################

# global counters.
test_number = crash_number = 1

# global health flag.
target_healthy = True

# time to wait between test cases for a crash.
crash_wait_time = 3

# vmware snapshot revert time.
vmware_revert_wait_time = 60 * 3

########################################################################################################################

def access_violation_handler (debugger, dbg, context):
    global test_number
    global crash_number
    global target_healthy

    print
    print "test case #%d caused access violation #%d" % (test_number, crash_number)
    print

    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    # disassemble the instruction the exception occured at.
    disasm = debugger.disasm(exception_address)

    crash_log = open("crash-%d.log" % crash_number, "w+")

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

    crash_number  += 1
    target_healthy = false


def start_debugger (debugger, pid):
    debugger.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation_handler)
    debugger.attach(pid)
    debugger.debug_event_loop()

########################################################################################################################

while 1:
    # start up the target.
    os.system(target_start_command)

    # give the target some time to start up.
    time.sleep(vmware_revert_wait_time)

    debugger = pydbg_client(pydbg_host, pydbg_port)

    for (pid, proc) in debugger.enumerate_processes():
        if proc.lower() == target_name:
            break

    # thread out the debugger.
    thread.start_new_thread(start_debugger, (debugger, pid))

    # loop through test cases while the target is healthy, if it dies the main loop will restart it.
    while target_healthy:
        # generate a test case.
        start = int(time.time())
        os.system(codenomicon_command_line % test_number)
        print "test case #%d took %d seconds to transmit.\r" % (test_number, int(time.time()) - start),

        # give the target a window of opportunity to crash before moving on.
        time.sleep(crash_wait_time)

        # increment the test count
        test_number += 1

    print "target is not healthy ... restarting."
