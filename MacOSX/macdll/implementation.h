/*
 *  implementation.h
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 12/15/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 * test.
 */

#define MEM_COMMIT                     0x00001000
#define MEM_DECOMMIT                   0x00004000
#define MEM_IMAGE                      0x01000000
#define MEM_RELEASE                    0x00008000

#define PAGE_NOACCESS                  0x00000001
#define PAGE_READONLY                  0x00000002
#define PAGE_READWRITE                 0x00000004
#define PAGE_WRITECOPY                 0x00000008
#define PAGE_EXECUTE                   0x00000010
#define PAGE_EXECUTE_READ              0x00000020
#define PAGE_EXECUTE_READWRITE         0x00000040
#define PAGE_EXECUTE_WRITECOPY         0x00000080
#define PAGE_GUARD                     0x00000100
#define PAGE_NOCACHE                   0x00000200
#define PAGE_WRITECOMBINE              0x00000400

int attach(int pid, mach_port_t *ep);
int detach(int pid, mach_port_t *ep);
void get_task_threads(int pid, thread_act_port_array_t *thread_list, mach_msg_type_number_t *thread_count);
int virtual_free(int pid, int address, int size);
int virtual_protect(int pid, int address, int size, int type);
char *allocate(int pid, int address, int size);
int read_memory(int pid, unsigned int addr, int len, char *data);
int write_memory(int pid, unsigned int addr, int len, char *data);
int get_context(thread_act_t thread, i386_thread_state_t *state);
int suspend_thread(unsigned int thread);
int resume_thread(unsigned int thread);
int set_context(thread_act_t thread, i386_thread_state_t *state);
int virtual_query(int pid, unsigned int *baseaddr, unsigned int *prot, unsigned int *size);
int allocate_in_thread(int threadId, int size);
task_t getport(int pid);