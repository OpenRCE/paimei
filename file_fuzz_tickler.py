#!c:\python\python.exe

"""
File Fuzz Tickler
Copyright (C) 2007 Pedram Amini <pedram.amini@gmail.com>

$Id: file_fuzz_tickler.py 222 2007-09-07 20:47:02Z pedram $

Description:
    Say you are fuzzing a file and you find a crash when corrupting a byte at offset X. You take a look at the crash
    dump and it doesn't look very promising. That is when this script comes in. Before you head down the painful path
    of tracking down the issue and determining if it is exploitable or not, apply some brute force:

        - add the original (base line) violating file to the crash bin.
        - fuzz through every 'smart' value at offset X
        - revert byte(s) at offset X to original which caused crash and fuzz through every 'smart' value at offset X-n
        - revert byte(s) at offset X-n to original and fuzz through every 'smart' value at offset X+1
        - choose random values for positions x-8 through x+8 and fuzz 100 times
        - each of these 1,020 test cases is stored in a crash bin so you can easily step through the different crash
          paths. explore with crash_bin_explorer.py utility
"""

import os
import sys
import utils
import struct
import random

from pydbg import *
from pydbg.defines import *

# globals.
try:
    USAGE            = "file_fuzz_ticker.py <parent program> <target file> <offending offset (dec.)> <fuzz width>\n"
    PUSH             = "\x68"
    CALL             = "\xE8"
    KILL_DELAY       = 5000     # milliseconds
    crash_bin        = utils.crash_binning.crash_binning()
    fuzz_library     = []
    max_num          = None
    struct_lengths   = {1:"B", 2:"H", 4:"L"}
    extra            = None

    # argument parsing.
    parent_program   = sys.argv[1]
    target_file      = sys.argv[2]
    offending_offset = int(sys.argv[3])
    fuzz_width       = int(sys.argv[4])
    extension        = "." + target_file.rsplit(".")[-1]
except:
    sys.stderr.write(USAGE)
    sys.exit(1)

# ensure path to parent program is sane.
if not os.path.exists(parent_program):
    sys.stderr.write("Path to parent program invalid: %s\n\n" % parent_program)
    sys.stderr.write(USAGE)
    sys.exit(1)

# ensure path to target file is sane.
if not os.path.exists(target_file):
    sys.stderr.write("Path to target file invalid: %s\n\n" % target_file)
    sys.stderr.write(USAGE)
    sys.exit(1)


########################################################################################################################
def add_integer_boundaries (integer):
    '''
    Add the supplied integer and border cases to the integer fuzz heuristics library.
    '''
    global fuzz_library, fuzz_width, max_num

    for i in xrange(-10, 10):
        case = integer + i

        # ensure the border case falls within the valid range for this field.
        if 0 <= case <= max_num:
            if case not in fuzz_library:
                fuzz_library.append(case)


def av_handler (dbg):
    global crash_bin, extra

    crash_bin.record_crash(dbg, extra)
    dbg.terminate_process()

    return DBG_CONTINUE


def bp_handler (dbg):
    # on initial break-in, create a new thread in the target process which executes:
    #   Sleep(sleep_time);
    #   ExitProcess(69);
    if dbg.first_breakpoint:
        insert_threaded_timer(dbg)

    # this shouldn't happen, but i'd like to know if it does.
    else:
        raw_input("how did we get here?....")

    return DBG_CONTINUE


def do_pydbg_dance (proggie, the_file):
    dbg = pydbg()
    dbg.load(proggie, the_file, show_window=False)
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
    dbg.set_callback(EXCEPTION_BREAKPOINT,       bp_handler)

    dbg.run()


def insert_threaded_timer (dbg):
    # resolve the addresses of kernel32.Sleep() and kernel32.ExitProcess()
    Sleep       = dbg.func_resolve_debuggee("kernel32", "Sleep")
    ExitProcess = dbg.func_resolve_debuggee("kernel32", "ExitProcess")

    # allocate some memory for our instructions.
    thread_address = address = dbg.virtual_alloc(None, 512, MEM_COMMIT, PAGE_EXECUTE_READWRITE)

    # assemble and write: PUSH sleep_time
    assembled = PUSH + struct.pack("<L", KILL_DELAY)
    dbg.write(address, assembled)
    address += len(assembled)

    # assemble and write: CALL kernel32.Sleep()
    relative_address = (Sleep - address - 5)  # -5 for the length of the CALL instruction
    assembled = CALL + struct.pack("<L", relative_address)
    dbg.write(address, assembled)
    address += len(assembled)

    # assemble and write: PUSH 69 (exit code)
    assembled = PUSH + struct.pack("<L", 69)
    dbg.write(address, assembled)
    address += len(assembled)

    # assemble and write: CALL kernel32.ExitProcess()
    relative_address = (ExitProcess - address - 5)  # -5 for the length of the CALL instruction
    assembled = CALL + struct.pack("<L", relative_address)
    dbg.write(address, assembled)
    address += len(assembled)

    # start a remote thread
    if not windll.kernel32.CreateRemoteThread(dbg.h_process, None, 0, thread_address, 0, 0, None):
        raise pdx("CreateRemoteThread() failed.", True)
########################################################################################################################


print "[*] tickling target file %s" % target_file
print "[*] through %s" % parent_program
print "[*] at mutant offset %d (0x%x)" % (offending_offset-1, offending_offset-1)
print "[*] with fuzz width %d" % fuzz_width

# initialize our fuzz library based on fuzz width.
max_num = 2** (fuzz_width * 8) - 1

add_integer_boundaries(0)
add_integer_boundaries(max_num / 2)
add_integer_boundaries(max_num / 3)
add_integer_boundaries(max_num / 4)
add_integer_boundaries(max_num / 8)
add_integer_boundaries(max_num / 16)
add_integer_boundaries(max_num / 32)
add_integer_boundaries(max_num)

print "[*] fuzz library initialized with %d entries" % len(fuzz_library)

# add the base line crash to the crash bin.
extra  = "BASELINE"
do_pydbg_dance(parent_program, target_file)

# read and store original data from target file.
fh   = open(target_file, "rb")
data = fh.read()
fh.close()


###########################################################
# fuzz through all possible fuzz values at offending offset.
###

print "[*] fuzzing at offending offset"
i = 0

for value in fuzz_library:
    extra  = "offending: 0x%x" % value
    top    = data[:offending_offset]
    bottom = data[ offending_offset + fuzz_width:]
    middle = struct.pack(">" + struct_lengths[fuzz_width], value)

    tmp_file = open("fuzz_tickle_tmp" + extension, "wb+")
    tmp_file.write(top + middle + bottom)
    tmp_file.close()

    assert(os.stat("fuzz_tickle_tmp" + extension).st_size != 0)
    assert(len(top + middle + bottom) == len(data))
    assert((top + middle + bottom)[offending_offset] == middle)

    do_pydbg_dance(parent_program, "fuzz_tickle_tmp" + extension)

    i       += 1
    crashes  = 0

    for bin in crash_bin.bins.itervalues():
        crashes += len(bin)

    print "\tcompleted %d of %d in this set (bins: %d, crashes: %d)\r" % (i, len(fuzz_library), len(crash_bin.bins), crashes),


###########################################################
# now fuzz through all possible fuzz values at offending offset - fuzz_width.
###

print "\n[*] fuzzing at offending offset - fuzz width"
i = 0
new_offset = offending_offset - fuzz_width

for value in fuzz_library:
    extra  = "offending-fuzz_width: 0x%x" % value
    top    = data[:new_offset]
    bottom = data[ new_offset + fuzz_width:]
    middle = struct.pack(">" + struct_lengths[fuzz_width], value)

    tmp_file = open("fuzz_tickle_tmp" + extension, "wb+")
    tmp_file.write(top + middle + bottom)
    tmp_file.close()

    assert(os.stat("fuzz_tickle_tmp" + extension).st_size != 0)
    assert(len(top + middle + bottom) == len(data))

    do_pydbg_dance("fuzz_tickle_tmp" + extension)

    i       += 1
    crashes  = 0

    for bin in crash_bin.bins.itervalues():
        crashes += len(bin)

    print "\tcompleted %d of %d in this set (bins: %d, crashes: %d)\r" % (i, len(fuzz_library), len(crash_bin.bins), crashes),


###########################################################
# now fuzz through all possible fuzz values at offending offset + fuzz_width.
###

print "\n[*] fuzzing at offending offset + fuzz width"
i = 0
new_offset = offending_offset + fuzz_width

for value in fuzz_library:
    extra  = "offending+fuzz_width: 0x%x" % value
    top    = data[:new_offset]
    bottom = data[ new_offset + fuzz_width:]
    middle = struct.pack(">" + struct_lengths[fuzz_width], value)

    tmp_file = open("fuzz_tickle_tmp" + extension, "wb+")
    tmp_file.write(top + middle + bottom)
    tmp_file.close()

    assert(os.stat("fuzz_tickle_tmp" + extension).st_size != 0)
    assert(len(top + middle + bottom) == len(data))

    do_pydbg_dance("fuzz_tickle_tmp" + extension)

    i       += 1
    crashes  = 0

    for bin in crash_bin.bins.itervalues():
        crashes += len(bin)

    print "\tcompleted %d of %d in this set (bins: %d, crashes: %d)\r" % (i, len(fuzz_library), len(crash_bin.bins), crashes),


###########################################################
# now do some random fuzzing around the offending offset.
###

print "\n[*] fuzzing with random data at offending offset +/- 8"

for i in xrange(100):
    extra  = "random: "
    top    = data[:offending_offset - 8]
    bottom = data[ offending_offset + 8:]
    middle = ""

    for o in xrange(16):
        byte    = random.randint(0, 255)
        middle += chr(byte)
        extra  += "%02x " % byte

    tmp_file = open("fuzz_tickle_tmp" + extension, "wb+")
    tmp_file.write(top + middle + bottom)
    tmp_file.close()

    assert(os.stat("fuzz_tickle_tmp" + extension).st_size != 0)
    assert(len(top + middle + bottom) == len(data))

    do_pydbg_dance(parent_program, "fuzz_tickle_tmp" + extension)

    crashes = 0

    for bin in crash_bin.bins.itervalues():
        crashes += len(bin)

    print "\tcompleted %d of %d in this set (bins: %d, crashes: %d)\r" % (i, len(fuzz_library), len(crash_bin.bins), crashes),


###########################################################
# print synopsis.
###

crashes = 0
for bin in crash_bin.bins.itervalues():
    crashes += len(bin)

print
print "[*] fuzz tickling complete."
print "[*] crash bin contains %d crashes across %d containers" % (crashes, len(crash_bin.bins))
print "[*] saving crash bin to file_fuzz_tickler.crash_bin"

crash_bin.export_file("file_fuzz_tickler.crash_bin")

# unlink the temporary file.
os.unlink("fuzz_tickle_tmp" + extension)