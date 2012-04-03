#
# $Id: __init__.py 237 2010-03-05 18:19:41Z pedram.amini $
#

__all__ = \
[
    "basic_block",
    "defines",
    "function",
    "instruction",
    "module",
]

from basic_block import *
from defines     import *
from function    import *
from instruction import *
from module      import *

# we don't want to make wx an required module for PIDA.
try:    import wx
except: pass

import cPickle
import zlib
import hashlib
import struct

########################################################################################################################
'''
These wrappers redirect to one of the dump/load routines. Currently the chosen vector is "custom". I left the other
approaches in this file mostly as a reminder of what *not* to do in the event that the need to improve the current
routine arises in the future.
'''

def dump (file_name, module, progress_bar=None):
    '''
    Dump the entire module structure to disk.

    @type  file_name:    String
    @param file_name:    File name to export to
    @type  module:       pida.module
    @param module:       Module to export to disk
    @type  progress_bar: String
    @param progress_bar: (Optional, Def=None) Can be one of "wx", "ascii" or None

    @rtype:  Boolean
    @return: True on success, False otherwise.
    '''

    if progress_bar:
        progress_bar = progress_bar.lower()

    return dump_custom(file_name, module, progress_bar)

def load (file_name, progress_bar=None):
    '''
    Restore a saved PIDA module from disk.

    @type  file_name: String
    @param file_name: File name to import from
    @type  progress_bar: String
    @param progress_bar: (Optional, Def=None) Can be one of "wx", "ascii" or None

    @rtype:  Mixed
    @return: Imported module on success, 0 on cancel and -1 on failure.
    '''

    if progress_bar:
        progress_bar = progress_bar.lower()

    return load_custom(file_name, progress_bar)


########################################################################################################################
def dump_custom (file_name, module, progress_bar=None):
    '''
    Dump the entire module structure to disk. This is done by first removing the large "nodes" attribute from the
    module. The modified module structure is then cPickle-ed, compressed and written to disk with a 4 byte size prefix.
    Next the number of nodes is calculated and written to disk as a 4 byte value. Finally, the "nodes" attribute is
    individually sliced and stored to disk through the above cPicle/compress method.

    @see: load_custom()

    @type  file_name:    String
    @param file_name:    File name to export to
    @type  module:       pida.module
    @param module:       Module to export to disk
    @type  progress_bar: String
    @param progress_bar: (Optional, Def=None) Can be one of "wx", "ascii" or None

    @rtype:  Boolean
    @return: True on success, False otherwise.
    '''

    fh = open(file_name, "wb+")

    # write the version signature disk.
    fh.write(struct.pack(">L", PIDA_VERSION))

    # remove the intra-object pointers and aliases.
    module.functions = None

    for func in module.nodes.values():
        func.module       = None
        func.basic_blocks = None

        for bb in func.nodes.values():
            bb.function = None
            bb.nodes    = None

            for ins in bb.instructions.values():
                ins.basic_block = None

    # detach the (possible large) nodes data structure from the module.
    nodes = module.nodes
    module.nodes = {}

    # write the "rest" of the data structure to disk.
    rest = zlib.compress(cPickle.dumps(module, protocol=2))
    fh.write(struct.pack(">L", len(rest)))
    fh.write(rest)

    # write the node count to disk.
    num_nodes         = len(nodes)
    count             = 0
    percent_indicator = 0

    fh.write(struct.pack(">L", num_nodes))

    # create a progress bar.
    if progress_bar == "wx":
        pb = wx.ProgressDialog("Storing %s to disk" % module.name,
            "%d total nodes to process." % num_nodes,
            maximum = num_nodes,
            style   = wx.PD_CAN_ABORT | wx.PD_AUTO_HIDE | wx.PD_APP_MODAL | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME)

    # slice up the nodes attribute and individually store each node to disk.
    for entry in nodes.values():
        count += 1
        node   = zlib.compress(cPickle.dumps(entry, protocol=2))

        fh.write(struct.pack(">L", len(node)))
        fh.write(node)

        if progress_bar == "wx":
            if not pb.Update(count):
                pb.Destroy()
                fh.close()
                return False

        elif progress_bar == "ascii":
            percent_complete = float(count) / float(num_nodes) * 100

            if percent_complete > 25 and percent_indicator == 0:
                print "25%",
                percent_indicator += 1
            elif percent_complete > 50 and percent_indicator == 1:
                print "50%",
                percent_indicator += 1
            elif percent_complete > 75 and percent_indicator == 2:
                print "75%",
                percent_indicator += 1

    # restore the nodes attribute.
    module.nodes = nodes

    if progress_bar == "wx":
        pb.Destroy()

    fh.close()
    return True


########################################################################################################################
def dump_orig (file_name, module, progress_bar=None):
    '''
    cPickle -> compress -> dump the entire module structure to disk. This was the original method used to store the
    PIDA data structure to disk. Unfortunately, for larger modules I was getting "out of memory" errors.

    @see: load_orig()

    @type  file_name: String
    @param file_name: File name to export to
    @type  module:    pida.module
    @param module:    Module to export to disk
    '''

    fh   = open(file_name, "wb+")
    dump = cPickle.dumps(module, protocol=2)
    comp = zlib.compress(dump)
    fh.write(comp)
    fh.close()


########################################################################################################################
def dump_shelve (file_name, module, progress_bar=None):
    '''
    @see: load_shelve()

    @type  file_name: String
    @param file_name: File name to export to
    @type  module:    pida.module
    @param module:    Module to export to disk
    '''

    import os
    import shelve

    os.unlink(file_name)

    sh = shelve.open(file_name, flag='n', writeback=True, protocol=2)

    # attributes from pida.module
    sh["name"]      = module.name
    sh["base"]      = module.base
    sh["depth"]     = module.depth
    sh["analysis"]  = module.analysis
    sh["signature"] = module.signature
    sh["version"]   = module.version
    sh["ext"]       = module.ext

    # attributes inherited from pgraph.graph
    sh["id"]        = module.id
    sh["clusters"]  = module.clusters
    sh["edges"]     = module.edges
    sh["nodes"]     = {}

    # we store the node dictionary piece by piece to avoid out of memory conditions.
    for key, val in module.nodes.items():
        sh["nodes"][key] = val
        sh.sync()

    sh.close()


########################################################################################################################
def load_custom (file_name, progress_bar=None):
    '''
    Restore a saved PIDA module from disk.

    @see: dump_custom()

    @type  file_name: String
    @param file_name: File name to import from

    @rtype:  Mixed
    @return: Imported module on success, 0 on cancel and -1 on failure.
    '''

    fh = open(file_name, "rb")

    # read and verify the version signature from disk.
    version = int(struct.unpack(">L", fh.read(4))[0])

    if version != PIDA_VERSION:
        return -1

    # read the "rest" of the data structure from disk.
    length = int(struct.unpack(">L", fh.read(4))[0])
    data   = fh.read(length)
    module = cPickle.loads(zlib.decompress(data))

    # read the node count from disk.
    num_nodes         = int(struct.unpack(">L", fh.read(4))[0])
    count             = 0
    percent_indicator = 0

    # create a progress bar.
    if progress_bar == "wx":
        pb = wx.ProgressDialog("Loading %s from disk" % module.name,
            "%d total nodes to process." % num_nodes,
            maximum = num_nodes,
            style   = wx.PD_CAN_ABORT | wx.PD_AUTO_HIDE | wx.PD_APP_MODAL | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME)

    # read each individual node structure from disk and merge it into the module.nodes dictionary.
    while 1:
        try:
            count += 1
            length = int(struct.unpack(">L", fh.read(4))[0])
        except:
            # EOF reached
            break

        data = fh.read(length)
        node = cPickle.loads(zlib.decompress(data))

        module.nodes[node.id] = node

        if progress_bar == "wx":
            if not pb.Update(count):
                pb.Destroy()
                fh.close()
                return 0

        elif progress_bar == "ascii":
            percent_complete = float(count) / float(num_nodes) * 100

            if percent_complete > 25 and percent_indicator == 0:
                print "25%",
                percent_indicator += 1
            elif percent_complete > 50 and percent_indicator == 1:
                print "50%",
                percent_indicator += 1
            elif percent_complete > 75 and percent_indicator == 2:
                print "75%",
                percent_indicator += 1

    if progress_bar == "wx":
        pb.Destroy()

    # restore the intra-object pointers and aliases.
    module.functions = module.nodes

    for func in module.nodes.values():
        func.module       = module
        func.basic_blocks = func.nodes

        for bb in func.nodes.values():
            bb.function = func
            bb.nodes    = bb.instructions

            for ins in bb.instructions.values():
                ins.basic_block = bb

    fh.close()
    return module


########################################################################################################################
def load_orig (file_name, progress_bar=None):
    '''
    @see: dump_orig()

    @type  name: String
    @param name: File name to import from

    @rtype:  pida.module
    @return: Imported module
    '''

    fh     = open(file_name, "rb")
    comp   = fh.read()
    dump   = zlib.decompress(comp)
    module = cPickle.loads(dump)
    fh.close()

    return module


########################################################################################################################
def load_shelve (file_name, progress_bar=None):
    '''
    Load a module from disk.

    @see: dump_shelve()

    @type  name: String
    @param name: File name to import from

    @rtype:  pida.module
    @return: Imported module
    '''

    import shelve

    sh  = shelve.open(file_name, flag='r', protocol=2)
    mod = module()

    # attributes from pida.module
    mod.name      = sh["name"]
    mod.base      = sh["base"]
    mod.depth     = sh["depth"]
    mod.analysis  = sh["analysis"]
    mod.signature = sh["signature"]
    mod.version   = sh["version"]
    mod.ext       = sh["ext"]

    # attributes inherited from pgraph.graph
    mod.id        = sh["id"]
    mod.clusters  = sh["clusters"]
    mod.edges     = sh["edges"]
    mod.nodes     = {}

    # we restore the node dictionary piece by piece to avoid out of memory conditions.
    for key, val in sh["nodes"].items():
        mod.nodes[key] = val

    return

########################################################################################################################
def signature (file_name):
    '''
    Create and return a signature (hash) for the specified file.

    @todo: Look into replacing this with something faster.

    @type  name: String
    @param name: File name to import from

    @rtype:  String
    @return: 32 character MD5 hex string
    '''

    try:
        fh = open(file_name, "rb")
    except:
        # try this on for size.
        fh = open("c:" + file_name, "rb")

    m  = hashlib.md5()

    m.update(fh.read())

    return m.hexdigest()
