#include <Python.h>
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
#include "implementation.h"

mach_port_t exception_port;

static PyObject *ContinueDebugEvent(PyObject *self, PyObject *args)
{
	const int pid, thread, status;
    	int sts;
	i386_thread_state_t state;
    	if (!PyArg_ParseTuple(args, "I", &thread))
        	return NULL;
	get_context(thread, &state);	
	sts = resume_thread(thread);
    	return Py_BuildValue("i", sts);
}

static PyObject *DebugActiveProcess(PyObject *self, PyObject *args)
{
    const int pid;
    int sts;

    if (!PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sts = attach(pid, &exception_port);
    return Py_BuildValue("i", sts);
}

static PyObject *EnumerateProcesses(PyObject *self, PyObject *args)
{
    	int ctl[4] = {0};
       	unsigned int size = 0;
    	struct kinfo_proc *kinfo = NULL;
       	int i, count;

    	ctl[0] = CTL_KERN;
       	ctl[1] = KERN_PROC;
    	ctl[2] = KERN_PROC_ALL;
        sysctl(ctl, 3, NULL, (size_t *) &size, NULL, 0); //Figure out the size we'll need
    	kinfo = calloc(1, size);
        sysctl(ctl, 3, kinfo, (size_t *) &size, NULL, 0); //Acutally go get it.
						
	count = size / sizeof(struct kinfo_proc);
						    
	PyObject *ret = PyTuple_New(count);
	for(i=0; i < count; i++){
		PyTuple_SetItem(ret, i, Py_BuildValue("(Is)", kinfo[i].kp_proc.p_pid, kinfo[i].kp_proc.p_comm));
	}
	free(kinfo);
	
	return ret;
}

static PyObject *DebugActiveProcessStop(PyObject *self, PyObject *args)
{
    const int pid;
    int sts;

    if (!PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sts = detach(pid);
    return Py_BuildValue("i", sts);
}

// ignores type
static PyObject *VirtualFreeEx(PyObject *self, PyObject *args)
{
    const int pid, address, size, type;
    int sts;

    if (!PyArg_ParseTuple(args, "iiii", &pid, &address, &size, &type))
        return NULL;

	sts = virtual_free(pid, address, size);

    return Py_BuildValue("i", sts);
}

static PyObject *VirtualProtectEx(PyObject *self, PyObject *args)
{
    const int pid, size, type;
	int *old;
    int sts;
	const int address;
//    if (!PyArg_ParseTuple(args, "iiiii", &pid, &address, &size, &type, &old))
	if (!PyArg_ParseTuple(args, "iiii", &pid, &address, &size, &type)){
		printf("Couldn't parse inputs, returning NULL!\n");
		printf("Was it a kernel address?\n");
        	return NULL;
	}

	sts = virtual_protect(pid, address, size, type);
    	return Py_BuildValue("i", sts);
}

// Ignores type and protections
static PyObject *VirtualAllocEx(PyObject *self, PyObject *args)
{
    const int pid, address, size, type, prot;
    int sts;

    if (!PyArg_ParseTuple(args, "iiiii", &pid, &address, &size, &type, &prot))
        return NULL;

	unsigned int addy = (unsigned int) allocate(pid, address, size);

    return Py_BuildValue("I", addy);
}

static PyObject *WaitForDebugEvent(PyObject *self, PyObject *args)
{
	const int pid, timeout;
	int ret;
	int ec, id;
	unsigned int eat, eref;

	if (!PyArg_ParseTuple(args, "ii", &pid, &timeout))
		return NULL;
	ret = my_msg_server(exception_port, timeout, &id, &ec, &eat, &eref);
	return Py_BuildValue("[i,i,i,I,I]", ret, id, ec, eat, eref); 
}

static PyObject *ReadProcessMemory(PyObject *self, PyObject *args)
{
   	const int pid, len;
	const unsigned int addr;
    	int sts;
	char *data;
	if (!PyArg_ParseTuple(args, "iIwi", &pid, &addr, &data, &len)){
		printf("Coudn't parse\n");
		return NULL;
	}
	sts = read_memory(pid, addr, len, data);
	return Py_BuildValue("i", sts);
}

static PyObject *WriteProcessMemory(PyObject *self, PyObject *args)
{
        const int pid, len;
        const unsigned int  addr;
	char **data;
    	int sts;
//	if (!PyArg_ParseTuple(args, "iIwii", &pid, &addr, &data, &len, &count)){
	if (!PyArg_ParseTuple(args, "iIwi", &pid, &addr, &data, &len)){
		printf("Could not parse\n");
		return NULL;
	}
    	sts = write_memory(pid, addr, len, *data);
	PyObject *ret = Py_BuildValue("i", sts);
    	return ret;
}

static PyObject *EnumerateThreads(PyObject *self, PyObject *args)
{
        const int pid;
   	int i;
 
	if (!PyArg_ParseTuple(args, "i", &pid))
        	return NULL;

        thread_act_port_array_t thread_list;
        mach_msg_type_number_t thread_count;

	get_task_threads(pid, &thread_list, &thread_count);

        PyObject *ret = PyTuple_New(thread_count);
	for(i=0; i < thread_count; i++){
                PyTuple_SetItem(ret, i, Py_BuildValue("I", thread_list[i]));
        }
        return ret;
}

static PyObject *SuspendThread(PyObject *self, PyObject *args)
{
        const unsigned int thread;
        i386_thread_state_t state;
        int sts;

        if (!PyArg_ParseTuple(args, "I", &thread))
                return NULL;
        sts = suspend_thread(thread); 
        return Py_BuildValue("i", sts);
}

static PyObject *ResumeThread(PyObject *self, PyObject *args)
{
        const unsigned int thread;
        i386_thread_state_t state;
	int sts, i;
	kern_return_t ret;
        unsigned int size = THREAD_BASIC_INFO_COUNT;
	struct thread_basic_info info;

        if (!PyArg_ParseTuple(args, "I", &thread))
                return NULL;

	sts = resume_thread(thread);
        return Py_BuildValue("i", sts);
}

static PyObject *TerminateProcess(PyObject *self, PyObject *args)
{
        int pid, exitcode, sts;

        if (!PyArg_ParseTuple(args, "ii", &pid, &exitcode))
                return NULL;
        sts = kill(pid, 9);
	sts++;
        return Py_BuildValue("i", sts);
}       

static void printcontext(i386_thread_state_t *state){
	printf("eax: %x\nebx: %x\necx: %x\nedx: %x\nedi: %x\nesi: %x\nebp: %x\nesp: %x\nss: %x\neflags: %x\neip: %x\ncs: %x\nds: %x\nes: %x\nfs: %x\ngs: %x\n", state->eax, state->ebx, state->ecx, state->edx, state->edi, state->esi, state->ebp, state->esp, state->ss, state->eflags, state->eip, state->cs, state->ds, state->es, state->fs, state->gs);
}


static PyObject *GetThreadContext(PyObject *self, PyObject *args)
{
        const unsigned int thread;
	i386_thread_state_t state;

    	if (!PyArg_ParseTuple(args, "I", &thread))
        	return NULL;

   	get_context(thread, &state);

s}

static PyObject *SetThreadContext(PyObject *self, PyObject *args)
{
        const unsigned int thread;
	i386_thread_state_t state;
	int sts;
	unsigned int x;

	// accept tuples , but should work for lists too 
        if (!PyArg_ParseTuple(args, "i(IIIIIIIIIIIIIIII)", &thread, &state.eax, &state.ebx, &state.ecx, &state.edx, &state.edi, &state.esi, &state.ebp, &state.esp, &state.ss, &state.eflags, &state.eip, &state.cs, &state.ds, &state.es, &state.fs, &state.gs))
                return NULL;
        sts = set_context(thread, &state);
	return Py_BuildValue("i", sts);	
}

static PyObject *VirtualQueryEx(PyObject *self, PyObject *args){
        const int pid;
        unsigned int addr;
	unsigned int prot;
	unsigned int size;
        unsigned sts;
    	if (!PyArg_ParseTuple(args, "iI", &pid, &addr)){        
		printf("Couldn't parse arguments in VirtualQuery\nWas it a kernel address?");
		return NULL;    
	}
	virtual_query(pid, &addr, &prot, &size);

	PyObject *ret = Py_BuildValue("[I,I]", addr, prot);
	return ret;
}

static PyMethodDef MacXMethods[] = {
	{"ContinueDebugEvent", ContinueDebugEvent, METH_VARARGS, "Continue debug event"},
        {"DebugActiveProcess", DebugActiveProcess, METH_VARARGS, "Attach to a process"},
	{"EnumerateThreads", EnumerateThreads, METH_VARARGS, "Get listing of threads"},
	{"EnumerateProcesses", EnumerateProcesses, METH_VARARGS, "Get process listing"},
	{"DebugActiveProcessStop", DebugActiveProcessStop, METH_VARARGS, "Detach from a process"},
	{"WaitForDebugEvent", WaitForDebugEvent, METH_VARARGS, "Continue an attached process"},
	{"SuspendThread", SuspendThread, METH_VARARGS, "Suspend thread"},
	{"ResumeThread", ResumeThread, METH_VARARGS, "Resume thread"},
	{"TerminateProcess", TerminateProcess, METH_VARARGS, "Terminate a process"},
	{"ReadProcessMemory", ReadProcessMemory, METH_VARARGS, "Read 4 bytes from memory of attached process"},
	{"WriteProcessMemory", WriteProcessMemory, METH_VARARGS, "Write 4 bytes into attached process's memory"},
	{"GetThreadContext", GetThreadContext, METH_VARARGS, "Get context for a thread"},
	{"SetThreadContext", SetThreadContext, METH_VARARGS, "Set context for a thread"},
	{"VirtualQueryEx", VirtualQueryEx, METH_VARARGS, "Get memory region information"},
      	{"VirtualAllocEx", VirtualAllocEx, METH_VARARGS, "Allocate memory"},
	{"VirtualFreeEx", VirtualFreeEx, METH_VARARGS, "Free memory"},
	{"VirtualProtectEx", VirtualProtectEx, METH_VARARGS, "VirtualProtect"},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initMacX(void){
	(void) Py_InitModule("MacX", MacXMethods);
}
