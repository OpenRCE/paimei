#
# IDA Python PIDA Database Generation Script
# Dumps the current IDB into a .PIDA file.
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: pida_dump.py 194 2007-04-05 15:31:53Z cameron $
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

import time
import pida

depth    = None
analysis = pida.ANALYSIS_NONE

while not depth:
    depth = AskStr("full", "Depth to analyze? (full, functions|func, basic blocks|bb)")
    
    if depth:
        depth = depth.lower()

    if   depth in ["full"]:                depth = pida.DEPTH_FULL
    elif depth in ["functions", "func"]:   depth = pida.DEPTH_FUNCTIONS
    elif depth in ["basic blocks", "bb"]:  depth = pida.DEPTH_BASIC_BLOCKS
    else:
        Warning("Unsupported depth: %s\n\nValid options include:\n\t- full\n\t- functions\n\t- basic blocks" % depth)
        depth = None

choice = AskYN(1, "Propogate nodes and edges for API calls (imports)?")

if choice == 1:
    analysis |= pida.ANALYSIS_IMPORTS

choice = AskYN(1, "Enumerate RPC interfaces and dispatch routines?")

if choice == 1:
    analysis |= pida.ANALYSIS_RPC


output_file = AskFile(1, GetInputFile() + ".pida", "Save PIDA file to?")

if not output_file:
    Warning("Cancelled.")
else:
    print "Analyzing IDB..."
    start = time.time()

    try:
        signature = pida.signature(GetInputFilePath())
    except:
        print "PIDA.DUMP> Could not calculate signature for %s, perhaps the file was moved?" % GetInputFilePath()
        signature = ""

    module = pida.module(GetInputFile(), signature, depth, analysis)
    print "Done. Completed in %f seconds.\n" % round(time.time() - start, 3)

    print "Saving to file...",
    start = time.time()
    pida.dump(output_file, module, progress_bar="ascii")
    print "Done. Completed in %f seconds." % round(time.time() - start, 3)

    # clean up memory.
    # XXX - this is not working...
    del(module)