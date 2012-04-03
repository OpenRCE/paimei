/*
 *  MacDll.h
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 12/26/06.
 *  Copyright 2006. All rights reserved.
 *
 */

#include <mach/mach.h>
#include "windows.h"
#include "implementation.h"
#include "Exception.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <string.h>
#include <mach/thread_status.h>
#include <unistd.h> 
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>

// All prototypes compliments of MSDN

// "Implemented"
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
BOOL CloseHandle(HANDLE hObject);
BOOL DebugActiveProcess(DWORD dwProcessId);
BOOL WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
BOOL DebugSetProcessKillOnExit(BOOL KillOnExit);
BOOL DebugActiveProcessStop(DWORD dwProcessId);
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode);
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
BOOL CreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
DWORD ResumeThread(HANDLE hThread);
BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
DWORD SuspendThread(HANDLE hThread);
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL GetThreadSelectorEntry(HANDLE hThread, DWORD dwSelector, LPLDT_ENTRY lpSelectorEntry);



// TODO
HMODULE LoadLibraryA(LPCTSTR lpFileName);
BOOL FreeLibrary(HMODULE hModule);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
HANDLE GetCurrentProcess(void);
DWORD GetLastError(void);
DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments);
HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);
LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
DWORD GetMappedFileName(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL LookupPrivilegeValueA(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid);
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

void test(int pid);