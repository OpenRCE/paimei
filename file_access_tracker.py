#!/usr/bin/env python

'''
    File Access Tracker
    
    Copyright (C) 2006 Cody Pierce <codyrpierce@gmail.com>
    
    Description: This PyDbg script will attempt to track files being read
    or written too during execution. This is especially useful when
    tracking file format vulnerabilities. It is not perfect, and is
    dependent on the size of the file, and method of reading. Libraries
    can be added for tracking, and multiple heaps can also be monitored.

'''

######################################################################
#
# Includes
#
######################################################################

import sys
import os
import struct
import time

from pydbg import *
from pydbg.defines import *
from ctypes import *
import utils


DUPLICATE_SAME_ACCESS = 0x00000002
FILE_CURRENT          = 0x00000001

kernel32 = windll.kernel32

######################################################################
#
# Our data classes
#
######################################################################

class Breakpoint:
    breakpoints = []
    def __init__(self, address):
        self.address = address
    
        return True
    
    def set_breakpoint(self, dbg):
        dbg.bp_set(self.address)
        breakpoints.append(self.address)
       
        return True

######################################################################

class Handle:
    def __init__(self, handle):
        self.handle = handle
        
        return True
        
    def get_handle(self):
        return self.handle

######################################################################
    
class Buffer:
    def __init__(self, address):
        self.address = address
        self.buffer = ""
        
        return True

    def get_address(self):
        return self.address

    def get_buffer(self):
        return self.buffer

######################################################################
#
# Our function breakpoint handlers
#
######################################################################

def handler_breakpoint(dbg):
    if dbg.first_breakpoint:
        if not set_library_hooks(dbg):
            print "[!] Couldnt set breakpoints"
    
            sys.exit(-1)
    
    return DBG_CONTINUE

def restore_guards(dbg): 
    dbg.page_guard_restore() 
    
    return DBG_CONTINUE
    
def handler_buffer(dbg):
    if not dbg.memory_breakpoint_hit:
        return DBG_CONTINUE
    
    module = dbg.addr_to_module(dbg.exception_address).szModule
    for buffer in xrange(0, len(dbg.buffers)):
        if dbg.bp_is_ours_mem(dbg.buffers[buffer]["address"]):
            if module in dbg.filters:
                # We filter some dlls
                return DBG_CONTINUE
            
            if dbg.buffers[buffer]["last_hit"] == dbg.exception_address and dbg.violation_address <= dbg.buffers[buffer]["last_addr"] + 4:
                dbg.buffers[buffer]["loop_count"] -= 1
            else:
                dbg.buffers[buffer]["loop_count"] = dbg.loop_limit
            
            dbg.buffers[buffer]["last_addr"] = dbg.violation_address
            dbg.buffers[buffer]["last_hit"] = dbg.exception_address
            
            if dbg.buffers[buffer]["loop_count"] <= 0:
                #print "[!] Looping"
                                
                return DBG_CONTINUE
            
            print "[*] BP on buffer [%s] [0x%08x] [0x%08x %s]" % (module, dbg.violation_address, dbg.exception_address, dbg.disasm(dbg.exception_address))
            
            #if dbg.mnemonic.startswith("rep"):
            #    dbg.page_guard_clear()
            #    dbg.bp_set(dbg.exception_address + dbg.instruction.length, restore=False, handler=restore_guards)

            dbg.bp_del_mem(dbg.buffers[buffer]["address"])
            #dbg.buffers.remove(dbg.buffers[buffer])
            
            return DBG_CONTINUE
    
    return DBG_CONTINUE

def handler_ReadFile(dbg, args, ret):
    buffer = {"address":args[1],
              "id":0,
              "loop_count":dbg.loop_limit,
              "size":dbg.flip_endian_dword(dbg.read_process_memory(args[3], 4)),
              "handler":handler_buffer,
              "last_addr":0x0,
              "last_hit":0x0}
    hi = args[0]
    requested_bytes = args[2]
    
    for lib in xrange(0, len(dbg.library)):
        if dbg.library[lib]["func"] == "ReadFile":
            break
        
    
    for handle in dbg.handles:
        if handle["id"] == hi:
            if dbg.filename.lower() in handle["filename"].lower():
                dbg.library[lib]["hit"] += 1
                buffer["id"] = dbg.library[lib]["hit"]
                if trackbuffer and buffer["id"] != dbg.trackbuffer:
                    
                    return DBG_CONTINUE
                
                print "[*] ReadFile %s [%d] [%d] Req:%d Read:%d\n[0x%08x][%s]" % (handle["filename"], buffer["id"], handle["id"], requested_bytes, buffer["size"], buffer["address"], dbg.smart_dereference(buffer["address"]))
                
                # print call stack, 15 calls deep
                print "CALL STACK:"
                call_stack = dbg.stack_unwind()
                call_stack.reverse()
                for address in call_stack[:15]:
                    print "%s: 0x%08x" % (dbg.addr_to_module(address).szModule, address)
                print "...\n---------------------"

                for dbgbuffer in dbg.buffers:
                    if buffer["address"] == dbgbuffer:
                        # We already have this buffer
                        return DBG_CONTINUE
                
                dbg.buffers.append(buffer)
                
                # Set up bp on buffer for future use
                if dbg.trackbuffer:
                    dbg.bp_set_mem(buffer["address"], buffer["size"], handler=buffer["handler"])
    
            break
    
    return DBG_CONTINUE

def incremental_read (dbg, addr, length):
    data = ""
    while length:
        try:
            data += dbg.read_process_memory(addr, 1)
        except:
            break

        addr   += 1
        length -= 1

    return data
        

def handler_CreateFileW(dbg, args, ret):
    handle = { "id":0,
               "filename":"",
               "pos":0
             }
    
    filename = dbg.get_unicode_string(incremental_read(dbg, args[0], 255))

    if filename:
        if dbg.filename.lower() in filename.lower():
            print "[*] CreateFileW %s returned 0x%x" % (filename, ret)
    else:
        return DBG_CONTINUE    
    
    handle["id"] = ret
    handle["filename"] = filename
    handle["handle"] = get_handle(dbg, ret)
    
    dbg.handles.append(handle)
    
    return DBG_CONTINUE

def handler_MapViewOfFile(dbg, args, ret):
    print "[*] MapViewOfFile [%x] return [0x%08x]"% (args[0], ret)
    
    return DBG_CONTINUE

def handler_SetFilePointerEx(dbg, args, ret):
    
    return DBG_CONTINUE

def handler_GetFileSizeEx(dbg, args, ret):
    
    return DBG_CONTINUE

def handler__read(dbg, args, ret):
    
    return DBG_CONTINUE

######################################################################
#
# Various set up routines before exection
#
######################################################################

def attach_target_proc(dbg, procname, filename):
    imagename = procname.rsplit('\\')[-1]
    print "[*] Trying to attach to existing %s" % imagename
    for (pid, name) in dbg.enumerate_processes():
        if imagename in name.lower():
            try:
                print "[*] Attaching to %s (%d)" % (name, pid)
                dbg.attach(pid)
            except:
                print "[!] Problem attaching to %s" % name
                
                return False
            
            return True
    
    try:
        print "[*] Trying to load %s %s" % (procname, filename)
        dbg.load(procname, "\"" + filename + "\"")
        
    except:
        print "[!] Problem loading %s %s" % (procname, filename)
        
        return False
    
    return True
     

def set_library_hooks(dbg):
    dbg.hooks = utils.hook_container()
    for lib in dbg.library:
        if not lib["on"]:
            continue
        
        address = dbg.func_resolve(lib["dll"], lib["func"])
        print "[*] Setting hook @ 0x%08x %s!%s" % (address, lib["dll"], lib["func"])
        try:
            dbg.hooks.add(dbg, address, lib["args"], None, lib["handler"])
        except:
            print "[!] Problem setting hook @ 0x%08x %s!%s" % (address, lib["dll"], lib["func"])
            
            return False
    
    return True

def get_handle(dbg, id):
    duped = HANDLE()
    if not kernel32.DuplicateHandle(dbg.h_process, id, kernel32.GetCurrentProcess(), byref(duped), 0, False, DUPLICATE_SAME_ACCESS):
        
        return False
    
    return duped

def close_handle(dbg, id):
    if not kernel32.CloseHandle(handle):
        return False
    
    for hi in xrange(0, len(dbg.handles)):
        if dbg.handles[hi]["id"] == id:
            dbg.handles.remove(hi)
            
            return True

    print "[!] Couldnt find handle id 0x%x" % id
    
    return False

######################################################################
#
# Static variables
#
######################################################################
filters = ["kernel32.dll", "user32.dll", "msvcrt.dll", "ntdll.dll"]
 
library = [{ "id":0,
             "dll":"kernel32",
             "func":"ReadFile",
             "handler":handler_ReadFile,
             "args":5,
             "hit":0,
             "on":True
           },
           { "id":1,
             "dll":"kernel32",
             "func":"CreateFileW",
             "handler":handler_CreateFileW,
             "args":7,
             "hit":0,
             "on":True
           },
           { "id":2,
             "dll":"kernel32",
             "func":"MapViewOfFile",
             "handler":handler_MapViewOfFile,
             "args":5,
             "on":False
           },
           { "id":3,  
             "dll":"kernel32",
             "func":"SetFilePointerEx",
             "handler":handler_SetFilePointerEx,
             "args":4,
             "on":False
           },
           { "id":4,
              "dll":"kernel32",
              "func":"GetFileSizeEx",
              "handler":handler_GetFileSizeEx,
              "args":2,
              "on":False
           },
           { "id":5,
             "dll":"msvcrt",
             "func":"_read",
             "handler":handler__read,
             "args":3,
             "on":True
           }]

handles = []
buffers = []
dbg = ""
loop_limit = 10

######################################################################
#
# Command line arguments
#
######################################################################

if len(sys.argv) < 3:
    print "Usage: %s <process name> <file name to track> [buffer to track]" % sys.argv[0]
    
    sys.exit(-1)

procname = sys.argv[1].lower()
filename = sys.argv[2].lower()
trackbuffer = False

if len(sys.argv) == 4:
    trackbuffer = int(sys.argv[3])

dbg = pydbg()
dbg.filters = filters
dbg.library = library
dbg.handles = handles
dbg.buffers = buffers
dbg.hooks = ""
dbg.procname = procname
dbg.filename = filename
dbg.loop_limit = loop_limit
dbg.trackbuffer = trackbuffer

dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

if not attach_target_proc(dbg, procname, filename):
    print "[!] Couldnt load/attach to %s" % procname
    
    sys.exit(-1)

dbg.debug_event_loop()

print "\nBuffers hit:\n"
for buf in dbg.buffers:
    print "%d" % buf["id"]
    print "=" * 72
    print "Address:      0x%08x" % buf["address"]
    print "Size:         0x%x" % buf["size"]
    print "Last Address: 0x%08x" % buf["last_addr"]
    print "Last Hit:     0x%08x\n" % buf["last_hit"]