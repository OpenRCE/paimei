#!c:\python\python.exe

#
# Proc Peek
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: proc_peek.py 194 2007-04-05 15:31:53Z cameron $
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
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import sys
import getopt
import struct
import time
import traceback
import utils

from pydbg import *
from pydbg.defines import *

USAGE = "DEPRECATED: See PAIMEIpeek\n"                                                      \
        "\nUSAGE: proc_peek.py "                                                            \
        "\n    <-r|--recon RECON FILE> name of proc_peek_recon output file"                 \
        "\n    [-p|--pid PID]          pid to attach to (must specify this or watch)"       \
        "\n    [-w|--watch PROC]       target name to watch for and attach to"              \
        "\n    [-i|--ignore PID]       ignore a specific PID when watching for a target"    \
        "\n    [-n|--noint]            disable interactive prompts"                         \
        "\n    [-q|--quiet]            disable run-time context dumps"                      \
        "\n    [-l|--log LOG FILE]     report to file instead of screen"                    \
        "\n    [-h|--host REMOTE HOST] connect to a pydbg server"                           \
        "\n    [-b|--boron KEYWORD]    alert us when a keyword is found within the context" \
        "\n    [-t|--track_recv]       enable recv() and recvfrom() hit logging"

ERR = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)

# globals.
peek_points = {}

ws2_recv = ws2_recvfrom = wsock_recv = wsock_recvfrom = None
retaddr = buffer = length = None

# peek point structure.
class peek_point:
    stack_depth = 0
    comment     = ""
    contexts    = []
    hit_count   = 0
    disabled    = 0


########################################################################################################################
### helper functions
########################################################################################################################


def boron_scan (ea, context_dump):
    """
    scans the context dump at ea for the command line specified boron tag. if found adds a comment to the peek point
    which is later output to the updated recon file. the passed in context dump should have been generated with
    prints_dots=False.
    """

    global peek_points
    global quiet, boron, noint     # command line flags.

    if not boron:
        return

    if context_dump.lower().find(boron) != -1:
        if not quiet:
            print ">>>>>>>>>>> boron tag '%s' was found ... adding comment." % boron

        boron_comment = " // " + "boron hit on '%s'" % boron

        # ensure comment doesn't already exist.
        if peek_points[ea].comment.find(boron_comment) == -1:
            peek_points[ea].comment += boron_comment

        if not noint:
            raw_input("enter to continue...")


def process_pp_hit (dbg):
    """
    if the hit peek point was not disabled, process it by incrementing the hit count, appending a new context dump and,
    depending on specified command line options, printing output to screen or interactively prompting the user for
    actions such as commenting or disabling the hit peek point.
    """

    global peek_points
    global quiet, noint     # command line flags.

    ea = dbg.exception_address

    if peek_points[ea].disabled > 0:
        return

    peek_points[ea].hit_count += 1

    dump = dbg.dump_context(stack_depth=peek_points[ea].stack_depth, print_dots=False)

    if not quiet:
        print
        print "hit #%d: %s" % (peek_points[ea].hit_count, peek_points[ea].comment)
        print dump

    # check for the existence of a boron tag in our current context.
    boron_scan(ea, dump)

    # check if the user wishes to start ignoring this peek point.
    hit_count = peek_points[ea].hit_count

    if not noint and peek_points[ea].disabled != -1 and hit_count in (5, 10, 20, 50, 75, 100, 150):
        print ">>>>>>>>>>> this peek point was hit %d times, disable it?" % hit_count

        try:
            key = raw_input("<y|n|v|q>[c] y=yes, n=no, v=never, c=comment> ")

            if key.lower() == "q":
                dbg.detach()
                return

            if key.lower() == "v":
                peek_points[ea].disabled = -1

            if key.lower().startswith("y"):
                peek_points[ea].disabled = hit_count

            if key.lower() in ("yc", "nc"):
                peek_points[ea].comment += " // " + raw_input("add comment> ")
        except:
            pass

    peek_points[ea].contexts.append(dump)


def track_recv_enter (dbg):
    """
    this function is called when a winsock function we wish to track is first hit. the return address, buffer size and
    buffer length are retrieved and a breakpoint is set on the return address for track_recv_exit() to handle.
    """

    # used in tracking hits to recv()/recvfrom()
    global ws2_recv, ws2_recvfrom, wsock_recv, wsock_recvfrom, retaddr, buffer, length

    ea = dbg.exception_address

    # ensure we are at the start of one of the winsock recv functions.
    if ea not in (ws2_recv, ws2_recvfrom, wsock_recv, wsock_recvfrom):
        return

    # ESP                 +4         +8       +C        +10
    # int recv     (SOCKET s, char *buf, int len, int flags)
    # int recvfrom (SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
    # we want these:                ^^^      ^^^

    retaddr = dbg.read_process_memory(dbg.context.Esp, 4)
    retaddr = struct.unpack("<L", retaddr)[0]

    buffer  = dbg.read_process_memory(dbg.context.Esp + 0x8, 4)
    buffer  = struct.unpack("<L", buffer)[0]

    length  = dbg.read_process_memory(dbg.context.Esp + 0xC, 4)
    length  = struct.unpack("<L", length)[0]

    if   ea == ws2_recv:       print "%08x call ws2.recv():"       % retaddr
    elif ea == ws2_recvfrom:   print "%08x call ws2.recvfrom():"   % retaddr
    elif ea == wsock_recv:     print "%08x call wsock.recv():"     % retaddr
    elif ea == wsock_recvfrom: print "%08x call wsock.recvfrom():" % retaddr

    dbg.bp_set(retaddr)


def track_recv_exit (dbg):
    """
    this function 'hooks' the return address of hit winsock routines and displays the contents of the received data.
    """

    global retaddr, buffer, length      # used in tracking hits to recv()/recvfrom()

    ea = dbg.exception_address

    if ea == retaddr:
        print "called from %08x with buf length: %d (0x%08x)" % (retaddr, length, length)
        print "actually received: %d (0x%08x)" % (dbg.context.Eax, dbg.context.Eax)

        if dbg.context.Eax != 0xFFFFFFFF:
            # grab the contents of the buffer based on the number of actual bytes read (from EAX).
            buffer = dbg.read_process_memory(buffer, dbg.context.Eax)

            print dbg.hex_dump(buffer)
            print

        dbg.bp_del(retaddr)

        retaddr = buffer = length = None


########################################################################################################################
### callback handlers.
########################################################################################################################


def handler_breakpoint (dbg):
    global peek_points

    # command line flags.
    global track_recv

    # used in tracking hits to recv()/recvfrom()
    global ws2_recv, ws2_recvfrom, wsock_recv, wsock_recvfrom

    # set all our breakpoints on the first windows driven break point.
    if dbg.first_breakpoint:
        # set breakpoints on our peek points.
        print "setting breakpoints on %d peek points" % len(peek_points.keys())
        dbg.bp_set(peek_points.keys())

        # if we want to track recv()/recvfrom(), do so.
        if track_recv:
            print "tracking calls to recv()/recvfrom() in ws2_32 and wsock32 ..."
            ws2_recv       = dbg.func_resolve("ws2_32",  "recv")
            ws2_recvfrom   = dbg.func_resolve("ws2_32",  "recvfrom")
            wsock_recv     = dbg.func_resolve("wsock32", "recv")
            wsock_recvfrom = dbg.func_resolve("wsock32", "recvfrom")

            try:    dbg.bp_set(ws2_recv)
            except: pass

            try:    dbg.bp_set(ws2_recvfrom)
            except: pass

            try:    dbg.bp_set(wsock_recv)
            except: pass

            try:    dbg.bp_set(wsock_recvfrom)
            except: pass

        return DBG_CONTINUE

    if track_recv:
        track_recv_enter(dbg)
        track_recv_exit (dbg)

    if peek_points.has_key(dbg.exception_address):
        process_pp_hit(dbg)

    return DBG_CONTINUE


def handler_access_violation (dbg):
    print "***** ACCESS VIOLATION *****"

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)

    print crash_bin.crash_synopsis()
    raw_input(" >>>>>>>>>> press key to continue <<<<<<<<<<<< ")
    dbg.terminate_process()


########################################################################################################################
### entry point
########################################################################################################################


# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "b:h:i:l:np:qr:tw:", \
        ["boron=", "host=", "ignore=", "log=", "noint", "pid=", "quiet", "recon=", "track_recv", "watch="])
except getopt.GetoptError:
    ERR(USAGE)

boron = pid = host = ignore = track_recv = quiet = noint = recon = watch = log_filename = log_file = None

for opt, arg in opts:
    if opt in ("-b", "--boron"):      boron          = arg
    if opt in ("-h", "--host"):       host           = arg
    if opt in ("-i", "--ignore"):     ignore         = int(arg)
    if opt in ("-l", "--log"):        log_filename   = arg
    if opt in ("-n", "--noint"):      noint          = True
    if opt in ("-p", "--pid"):        pid            = int(arg)
    if opt in ("-q", "--quiet"):      quiet          = True
    if opt in ("-r", "--recon"):      recon_filename = arg
    if opt in ("-t", "--track_recv"): track_recv     = True
    if opt in ("-w", "--watch"):      watch          = arg

if (not pid and not watch) or not recon_filename:
    ERR(USAGE)

# bail early if a log file was specified and we are unable to open it.
if log_filename:
    try:
        log_file = open(log_filename, "w+")
    except:
        ERR("failed opening %s for writing" % log_filename)

# read the list of peek points from the recon file.
try:
    fh = open(recon_filename)
except:
    ERR(USAGE)

for line in fh.readlines():
    line = line.rstrip("\r")
    line = line.rstrip("\n")

    # ignore commented out lines.
    if line[0] == "#":
        continue

    (address, stack_depth, comment) = line.split(":", 2)

    address     = long(address, 16)
    stack_depth = int(stack_depth)

    pp = peek_point()

    pp.stack_depth = stack_depth
    pp.comment     = comment
    pp.contexts    = []
    pp.hit_count   = 0

    peek_points[address] = pp

fh.close()

# if a remote host was specified, instantiate a pydbg client.
if host:
    print "peeking on remote host %s:7373" % host
    dbg = pydbg_client(host, 7373)
else:
    print "peeking locally"
    dbg = pydbg()

dbg.set_callback(EXCEPTION_BREAKPOINT,       handler_breakpoint)
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

try:
    # if specified, watch for the target process.
    if watch:
        print "watching for process: %s" % watch

        if ignore:
            print "ignoring PID %d" % ignore

        while watch:
            for (pid, name) in dbg.enumerate_processes():
                # ignore the optionally specified PID.
                if pid == ignore:
                    continue

                # if a name match was found, attach to the PID and continue.
                if name.find(".") != -1:
                    name = name.split(".")[0]

                if name.lower() == watch.lower():
                    print "process %s found on pid %d" % (name, pid)
                    watch = None
                    break

            time.sleep(1)

    # attach to the process and enter the debug event loop.
    # our first chance breakpoint handler will set the appropriate breakpoints.
    dbg.attach(pid)
    dbg.debug_event_loop()
except pdx, x:
    sys.stderr.write(x.__str__() + "\n")
    traceback.print_exc()


########################################################################################################################
### reporting
########################################################################################################################


print "debugger detached ... generating reports"

# determine whether we log to screen or file.
if log_file:
    write_line = lambda x: log_file.write("%s\n" % x)
else:
    write_line = lambda x: sys.stdout.write("%s\n" % x)

for address in peek_points:
    pp = peek_points[address]

    if len(pp.contexts) == 0:
        continue

    write_line("")
    write_line("*" * 80)
    write_line("peek point @%08x (%s) hit %d times" % (address, pp.comment, len(pp.contexts)))

    if pp.disabled:
        write_line("disabled at hit #%d" % pp.disabled)

    for context in pp.contexts:
        write_line(context)
        write_line("")

    write_line("*" * 80)
    write_line("")

if log_file:
    log_file.close()

# output the new recon file if we are in interactive mode or if a boron tag was specified.
if not noint or boron:
    try:
        new_recon_filename = recon_filename + ".%d" % pid
        new_recon          = open(new_recon_filename, "w+")
    except:
        ERR("failed opening %s for writing" % new_recon_filename)

    for address in peek_points:
        pp = peek_points[address]

        if pp.disabled:
            new_recon.write("#%08x:%d:%s\n" % (address, pp.stack_depth, pp.comment))
        else:
            new_recon.write("%08x:%d:%s\n" % (address, pp.stack_depth, pp.comment))

    new_recon.close()