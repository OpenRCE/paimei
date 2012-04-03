/*
 *  dyld.h
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 3/1/07.
 *  Copyright 2007 __MyCompanyName__. All rights reserved.
 *
 */
#define EXPORT __attribute__((visibility("default")))


int dyld_starts_here_p (task_t port, mach_vm_address_t addr);
int macosx_locate_dyld(int pid, unsigned int *addr);