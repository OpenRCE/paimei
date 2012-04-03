import os
import sys
import difflib
import code
import struct
import shelve

import pydbg


def monitor_updates (md):
    # grab the snapshot keys and sort alphabetically (we assume this is the correct order)
    snap_keys =  md.snapshots.keys()
    snap_keys.sort()
    
    for i in xrange(len(snap_keys)):
        self.diff(snap_keys[i], snap_keys[i+1])


class memory_differ:
    def __init__ (self, pid):
        """
        instantiate an internal pydbg instance and open a handle to the target process. we are not actually attaching!
        """
        
        self.dbg       = pydbg.pydbg()
        self.snapshots = {}

        # get debug privileges and open the target process. 
        self.dbg.get_debug_privileges()
        self.dbg.open_process(int(pid))


    def byte_diff_count (self, a, b):
        """
        assumes a and b are of the same length.
        """
        
        max_len = max(len(a), len(b))
        min_len = min(len(a), len(b))
        changes = max_len - min_len

        for idx in xrange(min_len):
            if a[idx] != b[idx]:
                changes += 1

        return changes


    def diff (self, key_a, key_b):
        """
        step through each block in snapshot-b and contrast with each block in snapshot-a.
        """

        a = self.snapshots[key_a]
        b = self.snapshots[key_b]

        diffs = []

        for address_b, block_b in b.iteritems():
            if address_b not in a.keys():
                diffs.append("new block in %s @%08x:%d" % (key_b, address_b, len(block_b.data)))
            else:
                block_a = a[address_b]
                tuple_a = (key_a, block_a.mbi.BaseAddress, len(block_a.data))
                tuple_b = (key_b, block_b.mbi.BaseAddress, len(block_b.data))

                if block_a.data == block_b.data:
                    diffs.append("%s.%08x:%d == %s.%08x:%d" % (tuple_a + tuple_b))
                else:
                    diff_count = (self.byte_diff_count(block_a.data, block_b.data), )
                    diffs.append("%s.%08x:%d != %s.%08x:%d [%d]" % (tuple_a + tuple_b + diff_count))

        return diffs
        

    def del_snap (self, key):
        del(self.snapshots[key])
        return self


    def export_block (self, block, filename, format="binary"):
        if format == "ascii":
            data = self.dbg.hex_dump(block.data)
            mode = "w+"
        else:
            data = block.data
            mode = "wb+"

        fh = open(filename, mode)
        fh.write(data)
        fh.close()
        
        return self

        
    def export_snap (self, key, path, prefix="", suffix="", ext="bin", format="binary"):
        if format != "binary" and ext == "bin":
            ext = "txt"

        for address, block in self.snapshots[key].iteritems():
            self.export_block(block, "%s/%s%08x%s.%s" % (path, prefix, address, suffix, ext), format)

        return self


    def find_all_occurences (self, needle, haystack, idx=0):
        found = []
        
        while 1:
            idx = haystack.find(needle, idx)
    
            if idx == -1:
                break
            
            found.append(idx)
            idx += len(needle)
    
        return found


    def get_snap (self, key):
        return self.snapshots[key]


    def load (self, filename):
        sh = shelve.open(filename, flag='r', protocol=2)

        # snag the snapshot key and remove it from the shelve.
        key = sh["key"]

        snapshot = {}
        for address, block in sh.iteritems():
            # the one NON address/block pair is the key/name pair, so skip that one.
            if address == "key":
                continue

            snapshot[int(address, 16)] = block

        self.snapshots[key] = snapshot
        sh.close()
        return self


    def save (self, key, filename):
        # clear out existing shelve.
        if os.path.exists(filename):
            os.unlink(filename)
        
        # open a new shelve and store the key.
        sh        = shelve.open(filename, flag='n', writeback=True, protocol=2)
        sh["key"] = key

        # we store the snapshot dictionary piece by piece to avoid out of memory conditions.
        for address, block in self.snapshots[key].iteritems():
            sh["%08x" % address] = block
            sh.sync()
    
        sh.close()
        return self


    def snap (self, key):
        """
        take a memory snapshot of the target process save the resulting dictionary to the internal snapshot dictionary
        under the specified key
        """
        
        self.dbg.process_snapshot(mem_only=True)

        snapshot = {}
        for block in self.dbg.memory_snapshot_blocks:
            snapshot[block.mbi.BaseAddress] = block
        
        self.snapshots[key] = snapshot
        return self


    def search (self, key, value, length="L"):
        matches = []

        for address, block in self.snapshots[key].iteritems():
            indices = []

            if type(value) in [int, long]:
                for endian in [">", "<"]:
                    indices.extend(self.find_all_occurences(struct.pack("%c%c" % (endian, length), value), block.data))
            else:
                indices.extend(self.find_all_occurences(value, block.data))
            
            for idx in indices:
                matches.append((address + idx, self.dbg.hex_dump(block.data[idx-32:idx+32], address + idx - 32)))

        return matches


########################################################################################################################
import readline
import rlcompleter

md = memory_differ(sys.argv[1])

imported_objects = {}
readline.set_completer(rlcompleter.Completer(imported_objects).complete)
readline.parse_and_bind("tab:complete")
code.interact(banner="Memory Differ\nSee dir(md) for help", local=locals())
    
"""
print "snapped %d blocks" % len(md.get_snap("a"))
raw_input("enter to take snap-B: ")
md.snap("b")
print "snapped %d blocks" % len(md.get_snap("b"))

print "diffing..."
for diff in md.diff("a", "b"):
    print diff

print "exporting..."
md.export_snap("a", "mem_diffs", suffix="_a")
md.export_snap("b", "mem_diffs", suffix="_b")
"""
