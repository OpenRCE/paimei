#
# DLL Injection/Ejection Helper
# Copyright (C) 2007 Justin Seitz <jms@bughunter.ca>
#
# $Id: injection.py 238 2010-04-05 20:40:46Z rgovostes $
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
@author:       Justin Seitz
@license:      GNU General Public License 2.0 or later
@contact:      jms@bughunter.ca
@organization: www.openrce.org
'''

import os.path

from pydbg           import *
from pydbg.defines   import *
from pydbg.my_ctypes import *

# macos compatability.
try:
    kernel32 = windll.kernel32
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))

########################################################################################################################
class inject:
    '''
    This class abstracts the ability to inject and eject a DLL into a remote process.
    '''

    ####################################################################################################################
    def __init__ (self):
        pass

    ####################################################################################################################
    def inject_dll (self, dll_path, pid):
        '''
        Inject a DLL of your choice into a running process.

        @type    dll_name: String
        @param   dll_name: The path to the DLL you wish to inject
        @type    pid:      Integer
        @param   pid:      The process ID that you wish to inject into

        @raise pdx: An exception is raised on failure.
        '''

        dll_len = len(dll_path)

        # get a handle to the process we are injecting into.
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        # now we have to allocate enough bytes for the name and path of our DLL.
        arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

        # Write the path of the DLL into the previously allocated space. The pointer returned
        written = c_int(0)
        kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))

        # resolve the address of LoadLibraryA()
        h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
        h_loadlib  = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

        # wow we try to create the remote thread.
        thread_id = c_ulong(0)
        if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
            # free the opened handles.
            kernel32.CloseHandle(h_process)
            kernel32.CloseHandle(h_kernel32)

            raise pdx("CreateRemoteThread failed, unable to inject the DLL %s into PID: %d." % (dll_path, pid), True)

        # free the opened handles.
        kernel32.CloseHandle(h_process)
        kernel32.CloseHandle(h_kernel32)


    ####################################################################################################################
    def eject_dll (self, dll_name, pid):
        '''
        Eject a loaded DLL from a running process.

        @type    dll_name: String
        @param   dll_name: The name of the DLL you wish to eject
        @type    pid:      Integer
        @param   pid:      The process ID that you want to eject a DLL from

        @raise pdx: An exception is raised on failure.
        '''

        # find the DLL and retrieve its information.
        ejectee = self.get_module_info(dll_name, pid)

        if ejectee == False:
            raise pdx("Couldn't eject DLL %s from PID: %d" % (dll_name, pid))

        # open the process.
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        # resolve the address of FreeLibrary()
        h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
        h_freelib  = kernel32.GetProcAddress(h_kernel32, "FreeLibrary")

        # now we try to create the remote thread hopefully freeing that DLL, the reason we loop is that
        # FreeLibrary() merely decrements the reference count of the DLL we are freeing. Once the ref count
        # hits 0 it will unmap the DLL from memory
        count = 0
        while count <= ejectee.GlblcntUsage:
            thread_id = c_ulong()
            if not kernel32.CreateRemoteThread(h_process, None, 0, h_freelib, ejectee.hModule, 0, byref(thread_id)):
                # free the opened handles.
                kernel32.CloseHandle(h_process)
                kernel32.CloseHandle(h_kernel32)

                raise pdx("CreateRemoteThread failed, couldn't run FreeLibrary()", True)

            count += 1

        # free the opened handles.
        kernel32.CloseHandle(h_process)
        kernel32.CloseHandle(h_kernel32)


    ##############################################################################
    def get_module_info (self, dll_name, pid):
        '''
        Helper function to retrieve the necessary information for the DLL we wish to eject.

        @type    dll_name: String
        @param   dll_name: The name of the DLL you wish to eject
        @type    pid:      Integer
        @param   pid:      The process ID that you want to eject a DLL from

        @raise pdx: An exception is raised on failure.
        '''

        # we create a snapshot of the current process, this let's us dig out all kinds of useful information, including
        # DLL info. We are really after the reference count so that we can decrement it enough to get rid of the DLL we
        # want unmapped
        current_process = MODULEENTRY32()
        h_snap          = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid)

        # check for a failure to create a valid snapshot
        if h_snap == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolHelp32Snapshot() failed.", True)

        # we have to initiliaze the size of the MODULEENTRY32 struct or this will all fail
        current_process.dwSize = sizeof(current_process)

        # check to make sure we have a valid list
        if not kernel32.Module32First(h_snap, byref(current_process)):
            kernel32.CloseHandle(h_snap)
            raise pdx("Couldn't find a valid reference to the module %s" % dll_name, True)

        # keep looking through the loaded modules to try to find the one specified for ejection.
        while current_process.szModule.lower() != dll_name.lower():
            if not kernel32.Module32Next(h_snap, byref(current_process)):
                kernel32.CloseHandle(h_snap)
                raise pdx("Couldn't find the DLL %s" % dll_name, True)

        # close the handle to the snapshot.
        kernel32.CloseHandle(h_snap)

        # return the MODULEENTRY32 structure of our DLL.
        return current_process
