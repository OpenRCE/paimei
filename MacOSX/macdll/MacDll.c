#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <stdio.h>

#include "MacDll.h"
#include "dyld.h"

#define EXPORT __attribute__((visibility("default")))

// Globals
static mach_port_t exception_port;
static int current_pid;
static BOOL kill_on_exit;
static struct kinfo_proc *kinfo;
static int kinfo_max;
static int kinfo_cur;
static thread_act_port_array_t thread_list;
static mach_msg_type_number_t thread_max;
static int thread_cur;
static int allocated_fs_base;


//Initializer.
__attribute__((constructor))
static void initializer(void) {
	kinfo = 0;
	allocated_fs_base = 0;
	//printf("[%s] initializer for me()\n", __FILE__);
}
      
// Finalizer.
__attribute__((destructor))
static void finalizer(void) {
	//printf("[%s] finalizer()\n", __FILE__);
}
          
EXPORT
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo){
	host_name_port_t myhost;
	host_basic_info_data_t hinfo;
	vm_size_t page_size;
	mach_msg_type_number_t count;
	
	myhost = mach_host_self();
	count = HOST_BASIC_INFO_COUNT;
	host_info(myhost, HOST_BASIC_INFO, (host_info_t) &hinfo, &count);
	host_page_size(myhost, &page_size);
	
	lpSystemInfo->dwPageSize = page_size;
	lpSystemInfo->dwNumberOfProcessors = hinfo.avail_cpus;
	return;
}

EXPORT
BOOL CloseHandle(HANDLE hObject){
	if(kinfo){
		free(kinfo);
		kinfo = 0;
	}
	
	// memory leak on thread stuff?
	return 1;
}

EXPORT
BOOL DebugActiveProcess(DWORD dwProcessId){
	kill_on_exit = 0;
	current_pid = dwProcessId;

	/* stuff that needs to be set each time you attach to a process */
	kinfo = 0;
	allocated_fs_base = 0;

	return attach(dwProcessId, &exception_port);
}

EXPORT
BOOL WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds){
	int ret, ec, id;
	unsigned int eat, eref;
	ret = my_msg_server(exception_port, dwMilliseconds, &id, &ec, &eat, &eref);

	lpDebugEvent->dwThreadId = id;
	lpDebugEvent->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode = ec;
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress = eat;
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[0] = 0; // just a guess
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[1] = (ULONG_PTR) eref;
	lpDebugEvent->dwProcessId = 0; // shouldn't need...

	return ret;
}

EXPORT
BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus){
	i386_thread_state_t state;
	get_context(dwThreadId, &state);	
	return resume_thread(dwThreadId);
}

EXPORT
BOOL DebugSetProcessKillOnExit(BOOL KillOnExit){
	kill_on_exit = KillOnExit;
	return 1;
}

EXPORT
BOOL DebugActiveProcessStop(DWORD dwProcessId){
	int ret = detach(dwProcessId, &exception_port);
	if(kill_on_exit){
		TerminateProcess(dwProcessId, 0);
	}
    return ret;
}

EXPORT
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode){
	int sts = kill(hProcess, 9);
//	printf("Just did kill on %d", hProcess);
	sts++;
	return sts;
}

EXPORT
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID){
	//fprintf(stderr, "CreateToolhelp32Snapshot %lx %ld\n", dwFlags, th32ProcessID);
	int ctl[4] = {0};
	unsigned int size = 0;
	
/* Collect process info */
	ctl[0] = CTL_KERN;
	ctl[1] = KERN_PROC;
	ctl[2] = KERN_PROC_ALL;
	sysctl(ctl, 3, NULL, (size_t *) &size, NULL, 0); //Figure out the size we'll need
	kinfo = calloc(1, size);
	sysctl(ctl, 3, kinfo, (size_t *) &size, NULL, 0); //Acutally go get it.
	kinfo_max = size / sizeof(struct kinfo_proc);
	kinfo_cur = 0;
	
/* Collect Thread info */
	get_task_threads(th32ProcessID, &thread_list, &thread_max);
	thread_cur = 0;

	return 1;
}

EXPORT
BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte){
	if(thread_cur < thread_max){
		lpte->th32ThreadID = thread_list[thread_cur];
		lpte->th32OwnerProcessID = current_pid;
		thread_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte){
	if(thread_cur < thread_max){
		lpte->th32ThreadID = thread_list[thread_cur];
		lpte->th32OwnerProcessID = current_pid;
		thread_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe){
	if(kinfo_cur < kinfo_max){
		lppe->th32ProcessID = kinfo[kinfo_cur].kp_proc.p_pid;
		strncpy(lppe->szExeFile, kinfo[kinfo_cur].kp_proc.p_comm, MAX_PATH-1);  // memory leak?
		lppe->szExeFile[MAX_PATH-1] = 0;
		kinfo_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe){
	if(kinfo_cur < kinfo_max){
		lppe->th32ProcessID = kinfo[kinfo_cur].kp_proc.p_pid;
		strncpy(lppe->szExeFile, kinfo[kinfo_cur].kp_proc.p_comm, MAX_PATH-1);  // memory leak?
		lppe->szExeFile[MAX_PATH-1] = 0;
		kinfo_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext){
	mach_msg_type_number_t sc;

	i386_thread_state_t state;
	sc = i386_THREAD_STATE_COUNT;
	thread_get_state( hThread, i386_THREAD_STATE, (thread_state_t) &state, &sc);
	lpContext->Eax = state.eax;
	lpContext->Ebx = state.ebx;
	lpContext->Ecx = state.ecx;
	lpContext->Edx = state.edx;
	lpContext->Edi = state.edi;
	lpContext->Esi = state.esi;
	lpContext->Ebp = state.ebp;
	lpContext->Esp = state.esp;
	lpContext->SegSs = state.ss;
	lpContext->EFlags = state.eflags;
	lpContext->Eip = state.eip;
	lpContext->SegCs = state.cs;
	lpContext->SegDs = state.ds;
	lpContext->SegEs = state.es;
	lpContext->SegFs = state.fs;
	lpContext->SegGs = state.gs;

	x86_debug_state32_t debug;
	sc = x86_DEBUG_STATE32_COUNT;
	thread_get_state( hThread, x86_DEBUG_STATE32, (thread_state_t) &debug, &sc);
	lpContext->Dr0 = debug.dr0;
	lpContext->Dr1 = debug.dr1;
	lpContext->Dr2 = debug.dr2;
	lpContext->Dr3 = debug.dr3;
	lpContext->Dr6 = debug.dr6;
	lpContext->Dr7 = debug.dr7;

	return 1;
}

EXPORT
BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext){
	mach_msg_type_number_t sc;
	kern_return_t result;

	i386_thread_state_t state;
	state.eax = lpContext->Eax;
	state.ebx = lpContext->Ebx;
	state.ecx = lpContext->Ecx;
	state.edx = lpContext->Edx;
	state.edi = lpContext->Edi;
	state.esi = lpContext->Esi;
	state.ebp = lpContext->Ebp;
	state.esp = lpContext->Esp;
	state.ss = lpContext->SegSs;
	state.eflags = lpContext->EFlags;
	state.eip = lpContext->Eip;
	state.cs = lpContext->SegCs;
	state.ds = lpContext->SegDs;
	state.es = lpContext->SegEs;
	state.fs = lpContext->SegFs;
	state.gs = lpContext->SegGs;	
	sc = i386_THREAD_STATE_COUNT;
	result = thread_set_state( hThread, i386_THREAD_STATE, (thread_state_t) &state, sc);
	if(result != KERN_SUCCESS){
		return 0;
	}

	x86_debug_state32_t debug;
	debug.dr0 = lpContext->Dr0;
	debug.dr1 = lpContext->Dr1;
	debug.dr2 = lpContext->Dr2;
	debug.dr3 = lpContext->Dr3;
	debug.dr6 = lpContext->Dr6;
	debug.dr7 = lpContext->Dr7;
	sc = x86_DEBUG_STATE32_COUNT;
	result = thread_set_state( hThread, x86_DEBUG_STATE32, (thread_state_t) &debug, sc);
	if(result != KERN_SUCCESS){
		return 0;
	}
	
	return 1;
}

EXPORT
BOOL CreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
	pid_t pid = vfork();
	//printf("Creating process %s %s\n", lpApplicationName, lpCommandLine);
	if(pid == 0){
		char commandline[256];
		strncpy(commandline, lpCommandLine, 255);
		commandline[255] = 0;
//		ptrace(PT_TRACE_ME, 0, 0, 0);
		// parse command line;
		int i=0;
		char *p = strchr(commandline, ' ');
		char *q = commandline;
		char *argv[16];
		while(p){
			*p = 0;
			argv[i++] = q;
			fflush(stdout);
			q = p + 1;
			p = strchr(commandline, ' ');
		}
		argv[i] = q;
		argv[i+1] = 0;
		//printf("Execing %s %s %s", argv[0], argv[1], argv[2]);
		fflush(stdout);
		execv(argv[0], argv);
		perror("Failed to execv!"); 
	} else {
		DebugActiveProcess(pid);
//		ptrace(PT_ATTACH, pid, 0, 0);
//		ptrace(PT_DETACH, pid, 0, 0);
		lpProcessInformation->dwProcessId = pid;
		lpProcessInformation->hProcess = pid;
	}
	return 1;
}

EXPORT
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId){
	return dwProcessId;
}

EXPORT
HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId){
	return dwThreadId;
}

EXPORT
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead){
	short sts;
	sts = read_memory(hProcess, (unsigned int) lpBaseAddress, nSize, lpBuffer);
	*lpNumberOfBytesRead = nSize;
	return sts;
}

EXPORT
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten){
	short sts = write_memory(hProcess, (unsigned int) lpBaseAddress, nSize, (char *) lpBuffer);
	*lpNumberOfBytesWritten = nSize;
	return sts;
}

EXPORT
DWORD ResumeThread(HANDLE hThread){
	return resume_thread(hThread);
}

EXPORT
DWORD SuspendThread(HANDLE hThread){
	return suspend_thread(hThread);
} 

// ignores allocationtype and protection
EXPORT
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){

	unsigned int addy = (unsigned int) allocate(hProcess, (int) lpAddress, dwSize);
	return (LPVOID) addy;
}

EXPORT
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType){
	return virtual_free(hProcess, (int) lpAddress, dwSize);
}

EXPORT
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength){
	unsigned int addr, prot, size = 0;
	addr = (unsigned int) lpAddress;
	
	if(virtual_query(hProcess, &addr, &prot, &size)){
		return 0;
	}

	lpBuffer->BaseAddress = addr;
	lpBuffer->Protect = prot;
	lpBuffer->RegionSize = size;
	lpBuffer->State = MEM_COMMIT; // dunno what this means or the equiv for mac, but needed for snapshotting.

	return sizeof(MEMORY_BASIC_INFORMATION);
}

EXPORT
DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh){
	struct stat sb;
	fstat(hFile, &sb);
	return sb.st_size;
}

EXPORT
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect){
	// Find old protection
	MEMORY_BASIC_INFORMATION Buffer;
	VirtualQueryEx(hProcess, lpAddress, &Buffer, dwSize);
	*lpflOldProtect = Buffer.Protect;
	// Set new protection
	return virtual_protect(hProcess, (int) lpAddress, dwSize, flNewProtect);
}

EXPORT
BOOL GetThreadSelectorEntry(HANDLE hThread, DWORD dwSelector, LPLDT_ENTRY lpSelectorEntry){
	//fprintf(stderr, "GetThreadSelectorEntry %d %ld \n", hThread, dwSelector);
/*
** Note: technically, some functions are called with threadid's instead of pids
**       which would break things except the pid is only really needed in those
**       fuctions the first time one of them is called.  What a hack 
*/
	if(!allocated_fs_base){
		char *fake_data = (char *) malloc(0x40);
		// Allocate some memory to put our fake data structures
		
		allocated_fs_base = (int) allocate(hThread, 0, 128);
		if(!allocated_fs_base){
			//printf("Couldn't allocate memory\n");
			return 0;
		}
		virtual_protect(hThread, allocated_fs_base, 128, PAGE_READWRITE);
		// Put some fake data to access
		memset(fake_data, 0x0, 0x40);
		memcpy(fake_data,	"\xff\xff\xff\xff" /*SEH*/ 
							"\xff\xff\xff\xbf" /* stack top */ 
							"\x00\x00\x00\xbf" /* stack bottom */
											, 12);
		int *p = (int *) (fake_data + 0x30); // SEH
		*p = htonl(allocated_fs_base);
		write_memory(hThread, allocated_fs_base, 0x40, fake_data);
	}

	lpSelectorEntry->BaseLow = allocated_fs_base & 0xffff;
	lpSelectorEntry->HighWord.Bytes.BaseMid = (allocated_fs_base & 0xff0000) >> 16;
	lpSelectorEntry->HighWord.Bytes.BaseHi = (allocated_fs_base & 0xff000000) >> 24;

	return 1;
}

//////////////////////////////////////TODOs//////////////////////////

EXPORT
HMODULE LoadLibraryA(LPCTSTR lpFileName){
	return 0;
}

EXPORT
BOOL FreeLibrary(HMODULE hModule){
	return 0;
}

EXPORT
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName){
	return 0xdeadbeef;
}

EXPORT
BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize){
	return 0;
}


EXPORT
BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme){
	return 0;
}

EXPORT
BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme){
	return 0;
}

EXPORT
HANDLE GetCurrentProcess(void){
	return 0;
}

EXPORT
DWORD GetLastError(void){
	return 0;
}

EXPORT
DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments){
	//printf("Error!\n");
	exit(1);
}

EXPORT
HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName){
	return 0;
}

EXPORT
LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap){
	return 0;
}

EXPORT
DWORD GetMappedFileName(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize){
	return 0;
}

EXPORT
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress){
	return 0;
}

EXPORT
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle){
	return 1;
}

EXPORT
BOOL LookupPrivilegeValueA(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid){
	return 1;
}

EXPORT
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength){
	return 1;
}
