/*
 *  dyld.c
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 3/1/07.
 *  Copyright 2007 __MyCompanyName__. All rights reserved.
 *
 */

#include <mach-o/ldsyms.h>
#include "MacDll.h"
#include "dyld.h"
#include "implementation.h"

EXPORT 
int macosx_locate_dyld(int pid, unsigned int *addr){
	kern_return_t kret = KERN_SUCCESS;
	struct vm_region_basic_info info;
	mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT;
	mach_vm_address_t test_addr = VM_MIN_ADDRESS;
	mach_vm_size_t size = 0;
	mach_port_t object_name = MACH_PORT_NULL;

	task_t port = getport(pid);

	do {
			kret = vm_region (port, (unsigned int *) &test_addr, (unsigned int *) &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &info_cnt, &object_name);

			if (kret != KERN_SUCCESS)
				return -1;

			if (dyld_starts_here_p (port, test_addr)){
				*addr = test_addr;
				return 1;
			}

			test_addr += size;

	} while (size != 0);
	return 0;
}

int dyld_starts_here_p (task_t port, mach_vm_address_t addr)
{
	mach_vm_address_t address = addr;
	mach_vm_size_t size = 0;
	struct vm_region_basic_info info;
	mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT;
	kern_return_t ret;
	mach_port_t object_name;
	vm_address_t data;
	vm_size_t data_count;

	struct mach_header *mh;

	ret = vm_region (port, (unsigned int *) &address, (unsigned int *) &size, VM_REGION_BASIC_INFO, (vm_region_info_t) & info, &info_cnt, &object_name);

	if (ret != KERN_SUCCESS)
		return 0;

	/* If it is not readable, it is not dyld. */

	if ((info.protection & VM_PROT_READ) == 0)
		return 0;

	ret = vm_read (port, address, size, &data, &data_count);

	if (ret != KERN_SUCCESS){
      /* Don't vm_deallocate the memory here, you didn't successfully get
         it, and deallocating it will cause a crash. */
		return 0;
	}

	/* If the vm region is too small to contain a mach_header, it also can't be
     where dyld is loaded */

	if (data_count < sizeof (struct mach_header)){
		ret = vm_deallocate (mach_task_self (), data, data_count);
		return 0;
	}

	mh = (struct mach_header *) data;

	/* If the magic number is right and the size of this region is big
     enough to cover the mach header and load commands, assume it is
     correct. */
	if ((mh->magic != MH_MAGIC && mh->magic != MH_CIGAM &&
		mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) ||
		mh->filetype != MH_DYLINKER ||
		data_count < sizeof (struct mach_header) + mh->sizeofcmds)
	{
		ret = vm_deallocate (mach_task_self (), data, data_count);
		return 0;
	}

	/* Looks like dyld, smells like dyld -- must be dyld! */
	ret = vm_deallocate (mach_task_self (), data, data_count);

	return 1;
}
