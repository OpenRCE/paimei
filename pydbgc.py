#!c:\python\python.exe

"""
PyDbg Just-In-Time Debugger
Copyright (C) 2006 Cody Pierce <codyrpierce@gmail.com>

$Id: pydbgc.py 233 2009-02-12 19:01:53Z codyrpierce $

Description:
    This quick and dirty hack gives you a PyDbg command line console with WinDbg-esque commands. One of the cooler
    features of this hack is the ability to step backwards. Yes really, you can step backwards.
"""


import sys, struct, string, re, signal

# This should point to paimei if its not in site-packages
#sys.path.append("C:\\code\\python\\paimei")

from ctypes import *
kernel32 = windll.kernel32

from pydbg import *
from pydbg.defines import *

class PydbgClient:
    ####################################################################################################################
    def __init__(self, dbg="", attach_breakpoint=True):
        self.dbg = dbg
        self.attach_breakpoint = attach_breakpoint

        self.steps = []
        self.breakpoints = []

        self.commands = []
        self.commands.append({"command": "bc",   "description": "Clear breakpoints",                  "handler": self.clear_breakpoints})
        self.commands.append({"command": "bd",   "description": "Delete a breakpoint (ex: db 2)",     "handler": self.delete_breakpoint})
        self.commands.append({"command": "bl",   "description": "List breakpoints",                   "handler": self.list_breakpoints})
        self.commands.append({"command": "bp",   "description": "Set a breakpoint (ex: bp 7ffdb000)", "handler": self.breakpoint})
        self.commands.append({"command": "dc",   "description": "Dump Data Charactes",                "handler": self.dump_data_characters})
        self.commands.append({"command": "dd",   "description": "Dump Data",                          "handler": self.dump_data})
        self.commands.append({"command": "g",    "description": "Resume Execution",                   "handler": self.go})
        self.commands.append({"command": "h",    "description": "Help",                               "handler": self.print_help})
        self.commands.append({"command": "help", "description": "Help",                               "handler": self.print_help})
        self.commands.append({"command": "k",    "description": "Call Stack",                         "handler": self.call_stack})
        self.commands.append({"command": "quit", "description": "Quit",                               "handler": self.quit})
        self.commands.append({"command": "r",    "description": "Modify a register (ex: r eax=10)",   "handler": self.register})
        self.commands.append({"command": "s",    "description": "Single Step",                        "handler": self.single_step})
        self.commands.append({"command": "sb",   "description": "Single Step Backwards",              "handler": self.step_back})
        self.commands.append({"command": "seh",  "description": "Current SEH",                        "handler": self.seh})
        self.commands.append({"command": "u",    "description": "Disassemble (ex: u 7ffdb000",        "handler": self.disassemble})


    ####################################################################################################################
    def breakpoint_handler(self, dbg):
        self.dbg = dbg

        # Initial module bp
        if dbg.first_breakpoint:
            if self.attach_breakpoint:
                signal.signal(signal.SIGBREAK, self.interrupt_handler)
                self.command_line()

            return DBG_CONTINUE

        self.command_line()

        return DBG_CONTINUE


    ####################################################################################################################
    def single_step_handler(self, dbg):
        self.dbg = dbg

        self.command_line()

        return DBG_CONTINUE


    ####################################################################################################################
    def interrupt_handler(self, signum, frame):
        #
        # I gotta figure out how to get a signal in pydbg back here
        sys.stdout.write("\n[*] Catching signal %d\n" % signum)
        if not kernel32.DebugBreakProcess(self.dbg.h_process):
            sys.stdout.write("[!] Problem breaking into process\n")

        return DBG_CONTINUE


    ####################################################################################################################
    def record_step(self):
        step = {}
        stack = ""
        (stacktop, stackbottom) = self.dbg.stack_range()
        current = stackbottom

        stack = self.dbg.read(current, stacktop - stackbottom)

        step["context"] = self.dbg.context
        step["stacktop"] = stacktop
        step["stackbottom"] = stackbottom
        step["stack"] = stack

        self.steps.append(step)

        return 0


    ####################################################################################################################
    def command_line(self):
        self.print_state()

        while True:
            sys.stdout.write("pydbgc> ")
            commandline = sys.stdin.readline().rstrip('\n')
            if re.search(' ', commandline):
                (command, args) = commandline.split(' ', 1)
            else:
                command = commandline
                args = ""

            rc = self.process_command(command, args)

            if rc == 1:
                return True

            sys.stdout.write("\n")

        return False


    ####################################################################################################################
    def print_state(self):
        #address = self.dbg.exception_address
        address = self.get_reg_value("eip")
        instruction = self.dbg.get_instruction(address)

        '''
        eax=7ffdf000 ebx=00000001 ecx=00000002 edx=00000003 esi=00000004 edi=00000005
        eip=7c901230 esp=0092ffcc ebp=0092fff4 iopl=0         nv up ei pl zr na pe nc
        cs=001b  ss=0023  ds=0023  es=0023  fs=0038  gs=0000             efl=00000246
        ntdll!DbgBreakPoint:
        7c901230 cc              int     3
        '''

        try:
            module = self.dbg.addr_to_module(address).szModule
        except:
            module = "N/A"

        sys.stdout.write("\n")
        sys.stdout.write("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n" %
        (self.get_reg_value("eax"), self.get_reg_value("ebx"), self.get_reg_value("ecx"),
        self.get_reg_value("edx"), self.get_reg_value("esi"), self.get_reg_value("edi")))
        sys.stdout.write("eip=%08x esp=%08x ebp=%08x\n\n" %
        (self.get_reg_value("eip"), self.get_reg_value("esp"), self.get_reg_value("ebp")))
        sys.stdout.write("%s!%08x  %s\n\n" %
        (module, address, self.dbg.disasm(address)))

        return 0


    ####################################################################################################################
    def process_command(self, command, args):
        for c in self.commands:
            if command == c["command"]:
                rc = c["handler"](args)
                return rc

        sys.stdout.write("Unknown command %s" % command)

        return -1


    ####################################################################################################################
    def go(self, *arguments, **keywords):
        self.dbg.single_step(False)
        sys.stdout.write("\nContinuing\n")

        return 1


    ####################################################################################################################
    def breakpoint(self, *arguments, **keywords):
        try:
            address = string.atol(arguments[0], 16)
        except:
            sys.stdout.write("Syntax error\n")
            return -1

        self.dbg.bp_set(address, restore=True, handler=self.breakpoint_handler)
        self.breakpoints.append(address)

        return 0


    ####################################################################################################################
    def disassemble(self, *arguments, **keywords):
        try:
            address = string.atol(arguments[0], 16)
        except:
            sys.stdout.write("Syntax error\n")
            return -1

        sys.stdout.write(self.dbg.disasm(address))

        return 0


    ####################################################################################################################
    def list_breakpoints(self, *arguments, **keywords):
        for i in xrange(0, len(self.breakpoints)):
            address = self.breakpoints[i]
            sys.stdout.write("[%d] %s!%08x\n" %
            (i, self.dbg.addr_to_module(address).szModule, address))

        return 0


    ####################################################################################################################
    def clear_breakpoints(self, *arguments, **keywords):
        for address in self.breakpoints:
            self.dbg.bp_del(address)

        self.breakpoints = []

        return 0


    ####################################################################################################################
    def delete_breakpoint(self, *arguments, **keywords):
        try:
            bp = int(arguments[0])
        except:
            sys.stdout.write("Syntax error\n")
            return -1

        self.dbg.bp_del(self.breakpoints[bp])
        self.breakpoints.remove(self.breakpoints[bp])

        return 0


    ####################################################################################################################
    def single_step(self, *arguments, **keywords):
        self.record_step()

        self.dbg.single_step(True)

        return 1


    ####################################################################################################################
    def step_back(self, *arguments, **keywords):
        step = self.steps.pop()
        context = step["context"]
        stack = step["stack"]

        current = step["stackbottom"]
        self.dbg.write(current, stack)

        self.dbg.set_thread_context(context)
        self.print_state()

        return 0


    ####################################################################################################################
    def register(self, *arguments, **keywords):
        arg1 = arguments[0].strip()

        if not re.search('=', arg1):
            self.print_state()

            return 0

        try:
            (register, value) = re.split('=', arg1)
            register = register.strip()
            value = string.atol(value.strip())
        except:
            sys.stdout.write("Syntax error\n")
            return -1

        self.set_reg_value(register, value)

        return 0


    ####################################################################################################################
    def dump_data(self, *arguments, **keywords):
        display = 128
        length = 0
        arg1 = arguments[0].strip()

        try:
            if re.search('\+', arg1):
                (address, offset) = arg1.split('+', 1)
                if re.search('[g-x]', address, re.I):
                    address = self.get_reg_value(address)
                else:
                    address = string.atol(address.stip(), 16)

                address = address + int(offset.strip())
            elif re.search('-', arg1):
                (address, offset) = arg1.split('-', 1)
                address = string.atol(address.strip(), 16) - int(offset.strip())
            else:
                if re.search('[g-x]', arg1, re.I):
                    address = self.get_reg_value(arg1)
                else:
                    address = string.atol(arg1, 16)
        except:
            sys.stdout.write("Syntax error\n")
            return -1


        while length <= display:
            if not length % 32:
                sys.stdout.write("\n%08x: " % (address + length))
            else:
                sys.stdout.write(" ")

            try:
                bytes = self.dbg.read(address + length, 4)
                sys.stdout.write("%08x" % (self.dbg.flip_endian_dword(bytes)))
            except:
                sys.stdout.write("????????")

            length += 4

        sys.stdout.write("\n")

        return 0


    ####################################################################################################################
    def dump_data_characters(self, *arguments, **keywords):
        # Todo

        return 0


    ####################################################################################################################
    def call_stack(self, *arguments, **keywords):
        callstack = self.dbg.stack_unwind()

        for address in callstack:
            sys.stdout.write("%s!%x\n" % (self.dbg.addr_to_module(address).szModule, address))

        return 0


    ####################################################################################################################
    def seh(self, *arguments, **keywords):
        seh = self.dbg.seh_unwind()

        for address, handler in seh:
            sys.stdout.write("%x:  %x\n" % (address, handler))

        return 0


    ####################################################################################################################
    def quit(self, *arguments, **keywords):
        self.clear_breakpoints()
        self.steps = []
        
        return 1


    ####################################################################################################################
    def print_help(self, *arguments, **keywords):
        sys.stdout.write("\n")
        for command in self.commands:
            sys.stdout.write("\t%s:\t%s\n" % (command["command"], command["description"]))

        return 0


    ####################################################################################################################
    def get_reg_value(self, register):
        context = self.dbg.get_thread_context(self.dbg.h_thread)

        if   register == "eax" or register == 0: return context.Eax
        elif register == "ecx" or register == 1: return context.Ecx
        elif register == "edx" or register == 2: return context.Edx
        elif register == "ebx" or register == 3: return context.Ebx
        elif register == "esp" or register == 4: return context.Esp
        elif register == "ebp" or register == 5: return context.Ebp
        elif register == "esi" or register == 6: return context.Esi
        elif register == "edi" or register == 7: return context.Edi
        elif register == "eip" or register == 8: return context.Eip

        return False


    ####################################################################################################################
    def set_reg_value(self, register, value):
        context = self.dbg.get_thread_context(self.dbg.h_thread)

        if   register == "eax" or register == 0: context.Eax = value
        elif register == "ecx" or register == 1: context.Ecx = value
        elif register == "edx" or register == 2: context.Edx = value
        elif register == "ebx" or register == 3: context.Ebx = value
        elif register == "esp" or register == 4: context.Esp = value
        elif register == "ebp" or register == 5: context.Ebp = value
        elif register == "esi" or register == 6: context.Esi = value
        elif register == "edi" or register == 7: context.Edi = value
        elif register == "eip" or register == 8: context.Eip = value

        self.dbg.set_thread_context(context)

        return True


########################################################################################################################


if __name__ == "__main__":
    def attach_target_proc(dbg, procname):
        '''
        Attaches to procname if it finds it otherwise loads.
        '''
        
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
            print "[*] Trying to load %s" % (procname)
            dbg.load(procname, "")

        except:
            print "[!] Problem loading %s" % (procname)

            return False

        return True

    ####################################################################################################################
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print "%s <process name> [attach breakpoint]" % sys.argv[0]
        sys.exit(-1)
    elif len(sys.argv) == 3:
        option = int(sys.argv[2])

        if option == 1:
            ab = True
        else:
            ab = False

    process = sys.argv[1]

    dbg = pydbg()
    pydbgc = PydbgClient(attach_breakpoint=ab)
    dbg.pydbgc = pydbgc

    dbg.set_callback(EXCEPTION_BREAKPOINT, dbg.pydbgc.breakpoint_handler)
    dbg.set_callback(EXCEPTION_SINGLE_STEP, dbg.pydbgc.single_step_handler)

    if not attach_target_proc(dbg, process):
        print "[!] Couldnt load/attach to %s" % process

        sys.exit(-1)

    dbg.debug_event_loop()