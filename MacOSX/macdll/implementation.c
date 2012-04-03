#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <string.h>
#include <mach/thread_status.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <implementation.h>
#include "Exception.h"

#define EXPORT __attribute__((visibility("default")))

/* NOTE:
#define VM_PROT_NONE    ((vm_prot_t) 0x00)
#define VM_PROT_READ    ((vm_prot_t) 0x01)
#define VM_PROT_WRITE   ((vm_prot_t) 0x02)
#define VM_PROT_EXECUTE ((vm_prot_t) 0x04)
*/

static task_t our_port = -1;  // initialized in attach

task_t getport(int pid){
	if(our_port == -1){
		task_t port;
        if(task_for_pid(mach_task_self(), pid, &port)){
                //fprintf(stderr, "Cannot get port, are you root?\n");
                return -1;
        }
		our_port = port;
	}
	return our_port;
}

int attach(int pid, mach_port_t *ep){
        //fprintf(stderr, "attach %x - calls exn_init\n", pid);
		our_port = -1;  // each time we attach, get a new port
		getport(pid);   // make sure port gets set
		
        *ep = init(pid);

//        if(ptrace(PT_ATTACH, pid, NULL, 0) < 0){
  //              perror("ptrace");
    //            return -1;
      //  }
        return 1;
}

int detach(int pid, mach_port_t *ep){
	//fprintf(stderr, "detatch %x\n", pid);
    mach_port_t me;
    me = mach_task_self();    

//  mach_port_names (mach_port_t task, mach_port_name_array_t *names, mach_msg_type_number_t *ncount, mach_port_type_array_t *types, mach_msg_type_number_t *tcount)
//mach_port_get_set_status (mach_port_t task, mach_port_t name, mach_port_array_t *members, mach_msg_type_number_t *count)
/*
	//	mach_port_name_t foo;
	mach_port_name_array_t *names;
	mach_msg_type_number_t ncount = 69;
	mach_port_type_array_t *types;
	mach_msg_type_number_t tcount = 69;
	mach_port_get_set_status(me, names, &ncount, types, &tcount);
	int i;
	for(i=0; i<ncount; i++){
		//fprintf(stderr, "%x\n", (unsigned int) names[i]);
		mach_port_deallocate(me, names[i]);
	}*/
	
	kern_return_t err = mach_port_deallocate(me, *ep);
	if(err!= KERN_SUCCESS){
		//printf("Failed to deallocate port!\n");
		if (err==KERN_INVALID_TASK){
			//fprintf(stderr, "Invalid task\n");
		} else if (err==KERN_INVALID_NAME) {
			//fprintf(stderr, "Invalid name\n");
		} else if (err==KERN_INVALID_RIGHT) {
			//fprintf(stderr, "Invalid right\n");
		}
	} else {
		//fprintf(stderr, "Deallocated port\n");
	}
	//      if(ptrace(PT_DETACH, pid,0,0) < 0){
//              perror("detach");
//              return -1;
//      }
        return 0;
}

void get_task_threads(int pid, thread_act_port_array_t *thread_list, mach_msg_type_number_t *thread_count){
	//fprintf(stderr, "get_task_threads %x\n", pid);
        task_t port =  getport(pid);
        task_threads(port, thread_list, thread_count);
	//fprintf(stderr, "Got %d threads from %d\n", *thread_count, pid);
}

int virtual_free(int pid, int address, int size){
    	int sts;
        task_t port = getport(pid);
	//fprintf(stderr, "virtual_free %x %x %x\n", pid, address, size);
        kern_return_t err = vm_deallocate(port, address, size);
        if(err!= KERN_SUCCESS){
                sts = 0;
        } else {
                sts = 1;
        }
        return sts;
}

static vm_prot_t winToXProtection(int type){
        vm_prot_t mac_prot = 0;
        switch(type){
                case PAGE_NOACCESS:
                        break;
                case PAGE_READONLY:
                        mac_prot = VM_PROT_READ;
                        break;
                case PAGE_READWRITE:
                        mac_prot = VM_PROT_READ | VM_PROT_WRITE;
                        break;
                case PAGE_EXECUTE:
                        mac_prot = VM_PROT_EXECUTE;
                        break;
                case PAGE_EXECUTE_READ:
                        mac_prot = VM_PROT_EXECUTE | VM_PROT_READ;
                        break;
                case PAGE_EXECUTE_READWRITE:
                        mac_prot = VM_PROT_EXECUTE | VM_PROT_READ | VM_PROT_WRITE;
                        break;
                case PAGE_GUARD:
                case PAGE_NOCACHE:
                case PAGE_WRITECOMBINE:
                default:
                        ;
        }
        return mac_prot;
}

static int XToWinProtection(vm_prot_t mac){
        int ret;
        switch(mac){
                case VM_PROT_READ:
                        ret = PAGE_READONLY;
                        break;
                case VM_PROT_READ | VM_PROT_WRITE:
                        ret = PAGE_READWRITE;
                        break;
                case VM_PROT_EXECUTE:
                        ret = PAGE_EXECUTE;
                        break;
                case VM_PROT_EXECUTE | VM_PROT_READ:
                        ret = PAGE_EXECUTE_READ;
                        break;
                case VM_PROT_EXECUTE | VM_PROT_READ | VM_PROT_WRITE:
                        ret = PAGE_EXECUTE_READWRITE;
                        break;
                default:
                        ret = PAGE_NOACCESS;
        }
        return ret;
}

int virtual_protect(int pid, int address, int size, int type){
        task_t port = getport(pid);
		//fprintf(stderr, "virtual_protect %x %x %x %x\n", pid, address, size, type);
        int sts;
        vm_prot_t mac_prot = winToXProtection(type);

		//fprintf(stderr, "vm_protect(%x, %x, %x, %x, %x)\n", port, address, size, FALSE, mac_prot);
        kern_return_t err = vm_protect(port, address, size, FALSE, mac_prot);
        if(err == KERN_SUCCESS){
                sts = 1;
        } else if(err == KERN_PROTECTION_FAILURE){
				sts = 1;  // hopefully they are setting up to read only
			//fprintf(stderr, "Failed to protect\n");
		} else {
                //fprintf(stderr, "Opps, got %d return from vm_protect\n", err);
                sts = 1;  // Probably memory is not allocated.
        }
        return sts;
}

char *allocate(int pid, int address, int size){
        char *data;
	//fprintf(stderr, "allocate %d %d %d\n", pid, address, size);
        task_t port = getport(pid);
        kern_return_t err = vm_allocate(port, (vm_address_t*) &data, size, VM_FLAGS_ANYWHERE);
        if(err!= KERN_SUCCESS){
                data = NULL;
        } 
		//fprintf(stderr, "ALLOCATE RETURNED WITH %x\n", (unsigned int) data);
        return data;
}

int read_memory(int pid, unsigned int addr, int len, char *data){
		//fprintf(stderr, "read_memory %x %x %x\n", pid, addr, len);
        mach_msg_type_number_t nread;
        task_t port = getport(pid);
        vm_read_overwrite(port, addr, len, (int) data, &nread);
        if(nread != len){
                //fprintf(stderr, "Error reading memory, requested %d bytes, read %d\n", len, nread);
//                return 0;  // bad
        }
      	return 1;
}

int write_memory(int pid, unsigned int addr, int len, char *data){
	//fprintf(stderr, "write_memory %x %x %x\n", pid, addr, len);
        task_t port = getport(pid);
		kern_return_t ret = vm_write(port, addr, (pointer_t) data, len);
        if(ret){
			//fprintf(stderr, "Failed to write to %x", addr);
				if(ret == KERN_PROTECTION_FAILURE)
					//fprintf(stderr, "error writing to %x: Specified memory is valid, but does not permit writing\n", addr);
				if(ret == KERN_INVALID_ADDRESS)
					//fprintf(stderr, "error writing to %x: The address is illegal or specifies a non-allocated region\n", addr);
				return 0;
        }	
        return 1;
}

int get_context(thread_act_t thread, i386_thread_state_t *state){
	//fprintf(stderr, "get_context %x: %x\n", thread, state->eip);
        mach_msg_type_number_t sc = i386_THREAD_STATE_COUNT;
        thread_get_state( thread, i386_THREAD_STATE, (thread_state_t) state, &sc);
        return 0;
}

int suspend_thread(unsigned int thread){
        int sts;
	//fprintf(stderr, "suspend_thread %x\n", thread);
        sts = thread_suspend(thread);
        if(sts == KERN_SUCCESS){
                sts = 0;
        } else {
                //fprintf(stderr, "Got bad return of %d\n", sts);
                sts = -1;
        }
        return sts;
}

int resume_thread(unsigned int thread){
        int i;
        kern_return_t ret;
	//fprintf(stderr, "resume_thread %x\n", thread);
        unsigned int size = THREAD_BASIC_INFO_COUNT;
        struct thread_basic_info info;

        ret = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t) &info, &size);
        if(ret != KERN_SUCCESS){
                //fprintf(stderr, "Failed to get thread info 1, got %d\n", ret);
// return ok for the case when the process is going away                return -1;
			return 0;
        }
        for(i = 0; i < info.suspend_count; i++){
                ret = thread_resume(thread);
                if(ret != KERN_SUCCESS){
                        //fprintf(stderr, "Failed to get thread info 2, got %d\n", ret);
                        return -1;
                }
        }
        return 0;
}

int virtual_query(int pid, unsigned int *baseaddr, unsigned int *prot, unsigned int *size){
        task_t port = getport(pid);
		//fprintf(stderr, "virtual_query %x %x %x\n", pid, *baseaddr, *size);
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
        struct vm_region_basic_info info;
        mach_port_t objectName = MACH_PORT_NULL;
		unsigned int requested_base = *baseaddr;
        kern_return_t result = vm_region(port, baseaddr, size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &objectName);

		// what can go wrong?  
		// No allocated pages at or after the requested addy
		// we just make up one for the rest of memory
        if(result != KERN_SUCCESS){
				//fprintf(stderr, "virtual_query failing case 1");
				*size = 0xffffffff - requested_base + 1;
				*prot = PAGE_NOACCESS;
                return 0;
        }
		// Mac scans ahead to the next allocated region, windows doesn't
		// We just make up a region at the base that isn't accessible so that iterating through memory works :/
		if(*baseaddr > requested_base){
				//fprintf(stderr, "virtual_query failing case 2, baseaddr=%x, requested_base=%x\n", *baseaddr, requested_base);
				*size = *baseaddr - requested_base;
				*baseaddr = requested_base;
				*prot = PAGE_NOACCESS;
                return 0;
        }
		
		// cool, worked
        *prot = XToWinProtection(info.protection);
		//fprintf(stderr, "Virtual query suceeded\n");
        return 0;
}

