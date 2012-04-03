#!/usr/bin/env python

# $Id: struct_spy.py 233 2009-02-12 19:01:53Z codyrpierce $

'''
    Struct Spy
    
    Copyright (C) 2006 Cody Pierce <codyrpierce@gmail.com>
    
    Description: This PyDbg will monitor structures being used based on
    their register+offset instruction. It will log all read, writes, and
    values, along with the addresses they occured at. It will then output
    this into a navigable html where you can drill down into the
    structure and its access. 
    
'''

######################################################################
#
# Includes
#
######################################################################

import sys
import os
import string
import struct
import time
import atexit

from pydbg import *
from pydbg.defines import *
from ctypes import *

kernel32 = windll.kernel32

######################################################################
#
# Our data classes
#
######################################################################

class Breakpoint:
    address = 0x00000000
    
    def __init__(self, address):
        self.address = address
        self.hit_count = 0
        self.description = "None"
        self.handler = self.breakpoint_handler
    
    def set_breakpoint(self, dbg):
        dbg.bp_set(self.address)
       
        return True

    def breakpoint_handler(self, dbg):
        
        return DBG_CONTINUE
    
class DbgException:
    current_id = 0
    
    def __init__(self, dbg):
        DbgException.current_id += 1
        self.id = DbgException.current_id
        
        self.address = dbg.exception_address
        self.module = dbg.addr_to_module(self.address).szModule
        
        if dbg.write_violation:
            self.direction = "write"
        else:
            self.direction = "read"
        
        self.violation_address = dbg.violation_address
        self.violation_thread_id = dbg.dbg.dwThreadId
        
        self.context = dbg.context
        self.context_dump = dbg.dump_context(self.context, print_dots=False)
        
        self.disasm = dbg.disasm(self.address)
        self.disasm_around = dbg.disasm_around(self.address)
        
        self.call_stack = dbg.stack_unwind()
        
        self.seh_unwind = dbg.seh_unwind

    def render_text(self, dbg, path):
        filename = "%s.%x" % (path, self.address)
        
        try:
            fh = open(filename + ".txt", "w")
        except:
            print "[!] Problem opening exception file %s" % filename
            sys.exit(-1)
        
        fh.write("\nException [0x%08x]\n" % self.address)
        fh.write("=" * 72)
        fh.write("\nDirection: %s\n" % self.direction)
        fh.write("Disasm: %s\n" % self.disasm)
        fh.write("Context:\n%s\n" % self.context_dump)
        fh.write("Call Stack:\n")
        for addr in self.call_stack:
            fh.write("  %s!0x%08x\n" % (dbg.addr_to_module(addr).szModule, addr))
        fh.write("\n")
        fh.close()
    
    def render_html(self, dbg, path):
        filename = "%s.%x" % (path, self.address)
        
        try:
            fh = open(filename + ".html", "w")
        except:
            print "[!] Problem opening exception file %s" % filename
            sys.exit(-1)
        
        fh.write("<html><head><title>Exception 0x%x</title></head><body><br>" % self.address)
        fh.write("\nException [0x%08x]<br>" % self.address)
        fh.write("=" * 72)
        fh.write("<br>Direction: %s<br>" % self.direction)
        fh.write("Disasm: %s<br>" % self.disasm)
        fh.write("Context:<br><pre>%s</pre><br>" % self.context_dump)
        fh.write("Call Stack:<br>")
        for addr in self.call_stack:
            fh.write("  %s!0x%08x<br>" % (dbg.addr_to_module(addr).szModule, addr))
        fh.write("<br>")
        fh.write("</body></html>")
        fh.close()
        
    def display(self,dbg):
        print "\nException [0x%08x]" % self.address
        print "=" * 72
        print "Direction: %s" % self.direction
        print "Disasm: %s" % self.disasm
        print "Context:\n%s" % self.context_dump
        print "Call Stack:" 
        for addr in self.call_stack:
            print "  %s!0x%08x" % (dbg.addr_to_module(addr).szModule, addr)
        print "\n"

class Offset:
    
    def __init__(self, parent, offset, size=4):
        self.parent = parent
        self.offset = offset
        self.size = size
        self.orig_data = ""
        self.data = ""
        self.dbg_exceptions = []
        self.modifications = []
        self.mod_addr = 0x00000000
        
        self.read_count = 0
        self.write_count = 0
        
        self.last_read = 0x00000000
        self.last_write = 0x00000000
        self.last_exception_id = 0
        self.last_module = 0x00000000
        
        self.handler = self.offset_handler
        
        self.description = "No description"
        
    def offset_handler(self, dbg):
        print "[*] Hit Offset Handler @ [%04d] 0x%08x 0x%08x" % (self.last_exception_id, dbg.exception_address, self.mod_addr)
        
        if dbg.exception_address != self.mod_addr:
            self.modifications.append((self.last_exception_id, dbg.read_process_memory(self.parent.address + self.offset, 4)))
        elif dbg.exception_address == self.mod_addr:
            self.modifications.append((self.last_exception_id, dbg.read_process_memory(self.parent.address + self.offset, 4)))
            #dbg.set_callback(EXCEPTION_SINGLE_STEP, dbg.exception_handler_single_step)
            dbg.single_step(False)
        
        return DBG_CONTINUE
    
    def render_text(self, dbg, path, excepts=True):
        filename = "%s.%x" % (path, self.offset)
        
        try:
            fh = open(filename + ".txt", "w")
        except:
            print "[!] Problem offset opening %s" % filename
            sys.exit(-1)
        
        fh.write("\nOffset [0x%08xx+0x%x]:\n" % (self.parent.address, self.offset))
        fh.write("=" * 72)
        fh.write("\nDescription: %s\n" % self.description)
        fh.write("Address: 0x%08x\n" % (self.parent.address + self.offset))
        fh.write("Size: %d\n" % self.size)
        fh.write("Read Count: %d\n" % self.read_count)
        fh.write("Last Read: 0x%08x\n" % self.last_read)
        fh.write("Write Count: %d\n" % self.write_count)
        fh.write("Last Write: 0x%08x\n" % self.last_write)
        fh.write("Last Module: %s\n" % self.last_module)
        if excepts:
            for dbgexcept in self.dbg_exceptions:
                fh.write("Exception: 0x%08x %s\n" % (dbgexcept.address, dbgexcept.disasm))
                dbgexcept.render_html(dbg, filename)
        fh.write("\n")
        fh.close()
    
    def render_html(self, dbg, path, excepts=True):
        filename = "%s.%x" % (path, self.offset)
        
        try:
            fh = open(filename + ".html", "w")
        except:
            print "[!] Problem offset opening %s" % filename
            sys.exit(-1)
        
        fh.write("<html><head><title>Offset 0x%08x+%x</title></head><body><br>" % (self.parent.address, self.offset))
        fh.write("\nOffset [0x%08x+0x%x]:<br>" % (self.parent.address, self.offset))
        fh.write("=" * 72)
        fh.write("<br>Description: %s<br>" % self.description)
        fh.write("Address: 0x%08x<br>" % (self.parent.address + self.offset))
        fh.write("Size: %d<br>" % self.size)
        fh.write("Read Count: %d<br>" % self.read_count)
        fh.write("Last Read: 0x%08x<br>" % self.last_read)
        fh.write("Write Count: %d<br>" % self.write_count)
        fh.write("Last Write: 0x%08x<br>" % self.last_write)
        fh.write("Last Module: %s<br>" % self.last_module)

        if excepts:
            fh.write("<table cellspacing=10><tr><td>")
            for dbgexcept in self.dbg_exceptions:
                fh.write("[%04d]: <a href=\"%s.%x.html\">0x%08x</a><br>" % (dbgexcept.id, filename.split('/')[-1], dbgexcept.address, dbgexcept.address))
                dbgexcept.render_html(dbg, filename)
            fh.write("</td><td>")
            for dbgexcept in self.dbg_exceptions:
                fh.write("[%.5s]<br>" % dbgexcept.direction)
            fh.write("</td><td>")
            for dbgexcept in self.dbg_exceptions:
                fh.write("%s<br>" % dbgexcept.disasm)
            fh.write("</td><td>")
            for (id,data) in self.modifications:
                fh.write("[%04d] 0x%08x<br>" % (id, struct.unpack("<L", data)[0]))
            fh.write("</td></tr></table>")
        
        fh.write("<br>")
        fh.write("</body></html>")
        fh.close()
        
    def display(self, dbg, excepts=True):
        print "\nOffset [0x%08xx+0x%x]:" % (self.parent.address, self.offset)
        print "=" * 72
        print "Description: %s" % self.description
        print "Address: 0x%08x" % (self.parent.address + self.offset)
        print "Size: %d" % self.size
        print "Read Count: %d" % self.read_count
        print "Last Read: 0x%08x" % self.last_read
        print "Write Count: %d" % self.write_count
        print "Last Write: 0x%08x" % self.last_write
        print "Last Module: %s" % self.last_module
        if excepts:
            for dbgexcept in self.dbg_exceptions:
                dbgexcept.display(dbg)
        print "\n"
    

class Structure:
    
    def __init__(self, address, length, timestamp):
        self.address = address
        self.size = length
        self.timestamp = timestamp
        self.orig_data = ""
        self.data = ""
        self.offsets = []
        self.handler = self.structure_handler
        self.description = "None"
        
    def exists(self, offset):
        for off in offsets:
            if offset == off.offset:
                return True
        
        return False
    
    def add_offset(self, offset):
        off = Offset(self, offset)
        self.offset.append(off)        
    
    def structure_handler(self, dbg):
        #print "[*] Hit Structure Handler"
        
        if not dbg.memory_breakpoint_hit:
            return DBG_CONTINUE
            
        module = dbg.addr_to_module(dbg.exception_address).szModule
        
        if dbg.bp_is_ours_mem(self.address):
            off = dbg.violation_address - self.address
            exists = False
            
            print "[*] Hit @ 0x%08x offset 0x%04x" % (dbg.violation_address, off)
            
            # Do the offset creation
            for o in xrange(0, len(self.offsets)):
                if self.offsets[o].offset == off:
                    offset = self.offsets[o]
                    offset.data = dbg.read_process_memory(dbg.violation_address, 1)
                    exists = True
                    break
            
            if not exists:
                offset = Offset(self, off)
                offset.orig_data = dbg.read_process_memory(dbg.violation_address, 1)
                offset.data = offset.orig_data
            
            dbgexcept = DbgException(dbg)
            offset.last_exception_id = dbgexcept.id
            
            if dbgexcept.direction == "read":
                offset.read_count += 1
                offset.last_read = dbgexcept.address
            else:
                offset.write_count += 1
                offset.last_write = dbgexcept.address
            
            offset.last_module = dbgexcept.module
            
            print "[*] [%s!0x%08x] %s [%s]" % (offset.last_module, dbgexcept.address, dbg.disasm(dbgexcept.address), dbgexcept.direction)
            
            offset.mod_addr = dbgexcept.address + dbg.instruction.length
            offset.dbg_exceptions.append(dbgexcept)
            
            # Store the new offset
            if not exists:
                self.offsets.append(offset)
            else:
                self.offsets[o] = offset
            
            # Get the modification data
            dbg.set_callback(EXCEPTION_SINGLE_STEP, offset.handler)  
            dbg.single_step(True)
            
        return DBG_CONTINUE
    
    def render_text(self, dbg, path, offsets=True):
        filename = "%s.%x" % (path, self.address)
        
        try:
            fh = open(filename + ".txt", "w")
        except:
            print "[!] Problem offset structure %s" % filename
            sys.exit(-1)
        
        fh.write("\nStructure [0x%08x]:\n" % self.address)
        fh.write("=" * 72)
        fh.write("\nAddress: 0x%08x\n" % self.address)
        fh.write("Size: %d\n" % self.size)
        fh.write("\n")
        for offset in self.offsets:
            fh.write("Offset: 0x%08x\n" % offset.offset)
            offset.render_text(dbg, filename)
        fh.write("\n\n")
        fh.close()
    
    def print_dump_html(self, fh, data):
        counter = 0
        pos = 0
        bold = False
        
        for char in data:
            for off in self.offsets:
                if off.offset == pos:
                    bold = True
                    break
                else:
                    bold = False
            
            if counter == 0:
                fh.write("0x%08x: " % pos)
                counter += 1
        
            if counter == 8:
                if bold:
                    fh.write("<b>0x%02x</b>  " % ord(char))
                else:
                    fh.write("0x%02x  " % ord(char))
                counter += 1
            elif counter < 16:
                if bold:
                    fh.write("<b>0x%02x</b> " % ord(char))
                else:
                    fh.write("0x%02x " % ord(char))
                counter += 1
            else:
                if bold:
                    fh.write("<b>0x%02x</b>  " % ord(char))
                else:
                    fh.write("0x%02x  " % ord(char))
                    
                while counter > 0:
                    char = data[pos - counter]
        
                    if counter == 8:
                        if char in string.printable:
                            fh.write("%c " % char)
                        else:
                            fh.write(". ")
                        counter -= 1
                    elif counter > 0:
                        if char in string.printable:
                            fh.write("%c" % char)
                        else:
                            fh.write(".")
                        counter -= 1
                    else:
                        if char in string.printable:
                            fh.write("%c<br>" % char)
                        else:
                            fh.write(".<br>")
                        counter = 0
                fh.write("<br>")
            pos += 1
        
        if counter:
            fh.write(" " * (80 - (counter * 5) + 5 + 1))
        
            if counter <= 8:
                fh.write(" ")
        
            while counter > 0:
                char = data[pos - counter]
        
                if counter == 8:
                    if char in string.printable:
                        fh.write("%c " % char)
                    else:
                        fh.write(". ")
                    counter -= 1
                elif counter > 0:
                    if char in string.printable:
                        fh.write("%c" % char)
                    else:
                        fh.write(".")
                    counter -= 1
                else:
                    if char in string.printable:
                        fh.write("%c<br>" % char)
                    else:
                        fh.write(".<br>")
                    counter = 0
        
        fh.write("<br>")
        
    def render_html(self, dbg, path, offsets=True):
        filename = "%s.%x" % (path, self.address)
        
        try:
            fh = open(filename + ".html", "w")
        except:
            print "[!] Problem offset structure %s" % filename
            sys.exit(-1)
            
        fh.write("<html><head><title>Structure 0x%08x</title></head><body><br>" % self.address)
        fh.write("\n<h2>Structure [0x%08x]:<br></h2>" % self.address)
        fh.write("=" * 72)
        fh.write("<br>Address: 0x%08x<br>" % self.address)
        fh.write("Size: %d<br>" % self.size)
        fh.write("<br>")
        fh.write("<table cellpadding=10><tr><td>")
        fh.write("          ")
        self.offsets.sort(cmp=numeri)
        for offset in self.offsets:
            fh.write("Offset: <a href=\"%s.%x.html\">0x%08x</a><br>" % (filename.split('/')[-1], offset.offset, offset.offset))
            offset.render_html(dbg, filename)
        fh.write("</td><td>")
        for offset in self.offsets:
            fh.write("[0x%02x] -> [0x%02x]<br>" % (struct.unpack("<B", offset.orig_data)[0], struct.unpack("<B", offset.data)[0]))
        fh.write("</td><td>")
        fh.write("<b>Before</b><br>")
        fh.write("<pre>")
        self.print_dump_html(fh, self.orig_data)
        fh.write("</pre>")
        fh.write("<br>")
        fh.write("<b>After</b><br>")
        fh.write("<pre>")
        self.print_dump_html(fh, self.data)
        fh.write("</pre>")
        fh.write("</td></tr></table>")
        fh.write("<br>")
        fh.write("</body></html>")
        fh.close()
        
    def display(self, dbg, offsets=True):
        print "\nStructure [0x%08x]:"
        print "=" * 72
        print "Address: 0x%08x" % self.address
        print "Size: %d" % self.size
        print "\n"
        for offset in self.offsets:
            if offset.write_count > 0:
                offset.display(dbg)
        print "\n\n"
        

######################################################################
#
# Our function breakpoint handlers
#
######################################################################

def handler_breakpoint(dbg):
    if dbg.first_breakpoint:
        # We need to set our code bp
        print "[*] Setting bp @ 0x%08x" % dbg.args["address"]
        
        # Might want to keep this but not for now
        dbg.bp_set(dbg.args["address"], restore=False, handler=handler_our_breakpoint)
        
        return DBG_CONTINUE
    
    return DBG_CONTINUE

def handler_our_breakpoint(dbg):
    if dbg.exception_address != dbg.args["address"]:
        
        return DBG_CONTINUE
    
    register = dbg.args["register"]
    value = get_register(dbg, register)
    
    if not value:
        print "[!] Problem getting %s" % register
        
        return DBG_CONTINUE
    
    print "[*] Hit code bp @ [0x%08x] %s = 0x%08x" % (dbg.exception_address, register, value)
    
    print "[*] Creating Structure(0x%08x, %d)" % (value, dbg.args["size"])
    dbg.structure = Structure(value, dbg.args["size"], dbg.args["timestamp"])
    dbg.structure.orig_data = dbg.read_process_memory(dbg.structure.address, dbg.structure.size)
    
    print "[*] Setting mem bp @ 0x%08x size %d" % (dbg.structure.address, dbg.structure.size)
    dbg.bp_set_mem(dbg.structure.address, dbg.structure.size, handler=dbg.structure.handler)
    
    return DBG_CONTINUE

######################################################################
#
# Various utility routines
#
######################################################################

def get_register(dbg, register):
    
    context = dbg.get_thread_context(dbg.h_thread)

    if   register == "EAX": return context.Eax
    elif register == "EBX": return context.Ebx
    elif register == "ECX": return context.Ecx
    elif register == "EDX": return context.Edx
    elif register == "ESI": return context.Esi
    elif register == "EDI": return context.Edi
    elif register == "ESP": return context.Esp
    elif register == "EBP": return context.Ebp
    elif register == "EIP": return context.Eip
    else: return False
    
    
    return False

def numeri(x, y):
    x = x.offset
    y = y.offset
    
    if   x  < y: return -1
    elif x == y: return 0
    else:        return 1

######################################################################
#
# Various set up routines before exection
#
######################################################################

def attach_target_proc(dbg, procname):
    imagename = procname.rsplit('\\')[-1]
    print "[*] Trying to attach to existing %s" % imagename
    for (pid, name) in dbg.enumerate_processes():
        if imagename in name:
            try:
                print "[*] Attaching to %s (%d)" % (name, pid)
                dbg.attach(pid)
            except:
                print "[!] Problem attaching to %s" % name
                
                return False
            
            return True
    
    try:
        print "[*] Trying to load %s %s" % (procname)
        dbg.load(procname, "")
        
    except:
        print "[!] Problem loading %s" % (procname)
        
        return False
    
    return True

def exitfunc(dbg):
    print "[!] Exiting"
    if dbg:
        print "[!] Cleaning up pydbg"
        if hasattr(dbg, "structure"):
            #dbg.structure.display(dbg)
            dbg.structure.data = dbg.read_process_memory(dbg.structure.address, dbg.structure.size)
            dbg.structure.render_html(dbg, "test" + "/" + dbg.args["timestamp"])
        dbg.cleanup()
        dbg.detach()
        
    sys.exit(0)

######################################################################
#
# Static variables
#
######################################################################
filters = ["kernel32.dll", "user32.dll", "msvcrt.dll", "ntdll.dll"]
dbg = ""

######################################################################
#
# Command line arguments
#
######################################################################

# track.py dps.exe 0x006AC928 ebx 256 [read|write|both]*
if len(sys.argv) < 5:
    print "Usage: %s <process name> <address of bp> <register> <size of struct>" % sys.argv[0]
    
    sys.exit(-1)

procname = sys.argv[1]
address = string.atol(sys.argv[2], 0)
register = sys.argv[3].upper()
size = int(sys.argv[4])
timestamp = time.strftime("%m%d%Y%H%M%S", time.localtime())

dbg = pydbg()
dbg.procname = procname
dbg.args = {"address":address, "register":register, "size":size, "timestamp":timestamp}

dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
atexit.register(exitfunc, dbg)

if not attach_target_proc(dbg, procname):
    print "[!] Couldnt load/attach to %s" % procname
    
    sys.exit(-1)

dbg.debug_event_loop()