#!c:\\python\\python.exe

"""
Crash Bin Explorer
Copyright (C) 2007 Pedram Amini <pedram.amini@gmail.com>

$Id: crash_bin_explorer.py 231 2008-07-21 22:43:36Z pedram.amini $

Description:
    Command line utility for exploring the results stored in serialized crash bin files. You can list all crashes
    categorized in buckets, view the details of a specific crash, or generate a graph of all crashes and crash paths
    based on stack-walk information.

    The 'extra' field is what specifies the test case number. It's up to you to label your test cases in however manner
    is appropriate to you.
"""

import getopt
import sys

import utils
import pgraph

USAGE = "\nUSAGE: crashbin_explorer.py <xxx.crashbin>"                                      \
        "\n    [-t|--test id]     dump the crash synopsis for a specific test case id"      \
        "\n    [-g|--graph name] generate a graph of all crash paths, save to 'name'.udg\n"

#
# parse command line options.
#

try:
    if len(sys.argv) < 2:
        raise Exception

    opts, args = getopt.getopt(sys.argv[2:], "t:g:", ["test=", "graph="])
except:
    print USAGE
    sys.exit(1)

test_id = graph_name = graph = None

for opt, arg in opts:
    if opt in ("-t", "--test"):  test_id    = arg
    if opt in ("-g", "--graph"): graph_name = arg

try:
    crashbin = utils.crash_binning.crash_binning()
    crashbin.import_file(sys.argv[1])
except:
    print "unable to open crashbin: '%s'." % sys.argv[1]
    sys.exit(1)

#
# display the full crash dump of a specific test case
#

if test_id:
    for bin, crashes in crashbin.bins.iteritems():
        for crash in crashes:
            if test_id == crash.extra:
                print crashbin.crash_synopsis(crash)
                sys.exit(0)

#
# display an overview of all recorded crashes.
#

if graph_name:
    graph = pgraph.graph()

for bin, crashes in crashbin.bins.iteritems():
    synopsis = crashbin.crash_synopsis(crashes[0]).split("\n")[0]

    if graph:
        crash_node       = pgraph.node(crashes[0].exception_address)
        crash_node.count = len(crashes)
        crash_node.label = "[%d] %s.%08x" % (crash_node.count, crashes[0].exception_module, crash_node.id)
        graph.add_node(crash_node)

    print "[%d] %s" % (len(crashes), synopsis)
    print "\t",

    for crash in crashes:
        if graph:
            last = crash_node.id
            for entry in crash.stack_unwind:
                address = long(entry.split(":")[1], 16)
                n = graph.find_node("id", address)

                if not n:
                    n       = pgraph.node(address)
                    n.count = 1
                    n.label = "[%d] %s" % (n.count, entry)
                    graph.add_node(n)
                else:
                    n.count += 1
                    n.label = "[%d] %s" % (n.count, entry)

                edge = pgraph.edge(n.id, last)
                graph.add_edge(edge)
                last = n.id
        print "%s," % crash.extra,

    print "\n"

if graph:
    fh = open("%s.udg" % graph_name, "w+")
    fh.write(graph.render_graph_udraw())
    fh.close()