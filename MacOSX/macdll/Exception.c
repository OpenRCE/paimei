/*
    File:       ExceptionTest.c

    Contains:   Test code for Mach exception handling.

    Written by: DTS

    Copyright:  Copyright (c) 2006 by Apple Computer, Inc., All Rights Reserved.

    Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc.
                ("Apple") in consideration of your agreement to the following terms, and your
                use, installation, modification or redistribution of this Apple software
                constitutes acceptance of these terms.  If you do not agree with these terms,
                please do not use, install, modify or redistribute this Apple software.

                In consideration of your agreement to abide by the following terms, and subject
                to these terms, Apple grants you a personal, non-exclusive license, under Apple's
                copyrights in this original Apple software (the "Apple Software"), to use,
                reproduce, modify and redistribute the Apple Software, with or without
                modifications, in source and/or binary forms; provided that if you redistribute
                the Apple Software in its entirety and without modifications, you must retain
                this notice and the following text and disclaimers in all such redistributions of
                the Apple Software.  Neither the name, trademarks, service marks or logos of
                Apple Computer, Inc. may be used to endorse or promote products derived from the
                Apple Software without specific prior written permission from Apple.  Except as
                expressly stated in this notice, no other rights or licenses, express or implied,
                are granted by Apple herein, including but not limited to any patent rights that
                may be infringed by your derivative works or by other works in which the Apple
                Software may be incorporated.

                The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
                WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
                WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
                PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
                COMBINATION WITH YOUR PRODUCTS.

                IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
                CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
                GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
                ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
                OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
                (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
                ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Change History (most recent first):

$Log: Exception.c,v $
Revision 1.2  2007/02/06 02:50:15  cmiller
Hardware breakpoints work.

Revision 1.1.1.1  2007/02/06 02:39:15  cmiller
sup

Revision 1.7  2007/01/02 14:34:10  cmiller
Works on test program.  So sweet.

Revision 1.6  2006/12/26 20:12:27  cmiller
Getting ready to go to pure dll way

Revision 1.5  2006/12/26 20:02:18  cmiller
This plus files used to work in the python case.  We're switching to a pure C implementation.

Revision 1.4  2006/12/18 18:33:19  cmiller
Can do one iteration!

Revision 1.3  2006/12/18 17:18:52  cmiller
Sort of works with the _identity raise exception technique

Revision 1.2  2006/12/17 02:25:35  cmiller
Added my_msg_server

Revision 1.1.1.1  2006/12/16 03:37:56  cmiller
Initial


*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

    // When we MIG our own exception server, it creates a handydandy header that we 
    // can just include.

#include "MachExceptionsServer.h"

#include "Exception.h"
#include "implementation.h"

static int thread_id;
static int exception_code;
static  int exception_at;
static int exception_ref;

// Windows exception codes
#define EXCEPTION_ACCESS_VIOLATION	0xC0000005
#define EXCEPTION_BREAKPOINT		0x80000003
#define EXCEPTION_GUARD_PAGE		0x80000001
#define EXCEPTION_SINGLE_STEP		0x80000004
#define EFLAGS_TRAP			0x00000100

int XToWinException(int ec){
	int ret;
	switch(ec){
		case EXC_BAD_ACCESS:
			ret = EXCEPTION_ACCESS_VIOLATION;
			break;
		case EXC_BREAKPOINT:
			ret = EXCEPTION_BREAKPOINT;
			break;
		case EXCEPTION_SINGLE_STEP:	// already converted
			ret = EXCEPTION_SINGLE_STEP;
			break;
		default:
			ret = EXC_SOFTWARE;  // why not
	}
	return ret;
}

// When we install our exception port, we always specify EXCEPTION_STATE_IDENTITY.  
// This means that the system will always call our catch_exception_raise_state_identity 
// routine.  catch_exception_raise and catch_exception_raise_state are present 
// purely for demostration purposes.

extern kern_return_t catch_exception_raise(
	mach_port_t             exception_port,
	mach_port_t             thread,
	mach_port_t             task,
	exception_type_t        exception,
	exception_data_t        code,
	mach_msg_type_number_t  codeCnt
)
{
    assert(false);
    return KERN_FAILURE;
/*
    if (exception != EXC_BREAKPOINT) {
		assert(false);
		return KERN_FAILURE;
	}

	suspend_thread(thread);
	thread_abort(thread);

// fixup
	i386_thread_state_t state;
	get_context(thread, &state);
	state.eip--;
	set_context(thread, &state);
	unsigned int addy = state.eip;
	virtual_protect(pid, addy, 1, 0x00000040);
	write_memory(pid, addy, 1, buf);
	virtual_protect(pid, addy, 1, 0x00000020);

	resume_thread(thread);
//	return KERN_FAILURE; //Trace/BPT trap
//	return KERN_SUCCESS; //Trace/BPT trap
//	return MIG_NO_REPLY; //Trace/BPT trap
	return KERN_INVALID_ARGUMENT; //Trace/BPT trap
*/
}

extern kern_return_t catch_exception_raise_state(
	mach_port_t             exception_port,
	exception_type_t        exception,
	const exception_data_t  code,
	mach_msg_type_number_t  codeCnt,
	int *                   flavor,
	const thread_state_t    old_state,
	mach_msg_type_number_t  old_stateCnt,
	thread_state_t          new_state,
	mach_msg_type_number_t *new_stateCnt
)
{
    assert(false);
    return KERN_FAILURE;
}

extern kern_return_t catch_exception_raise_state_identity(
	mach_port_t             exception_port,
	mach_port_t             thread,
	mach_port_t             task,
	exception_type_t        exception,
	exception_data_t        code,
	mach_msg_type_number_t  codeCnt,
	int *                   flavor,
	thread_state_t          old_state,
	mach_msg_type_number_t  old_stateCnt,
	thread_state_t          new_state,
	mach_msg_type_number_t *new_stateCnt
)
    // Handle a Mach exception.
    //
    // exception_port is the name of a receive (?) right for the port to which 
    // the exception was sent.
    //
    // thread is the name of a send right for the thread taking the exception.
    //
    // task is the name of a send right for the task taking the exception.
    // 
    // exception is the high-level exception code, for example, EXC_BREAKPOINT.
    //
    // code is a pointer to an array (of codeCnt elements) containing machine-specific 
    // information about the exception.  
    //
    // On entry, *flavor is the type of thread state information supplied in old_state.  
    // For example, x86_THREAD_STATE32 or PPC_THREAD_STATE.  This is the flavour you 
    // requested when you installed the exception port.  On error, *flavor is ignored.  
    // On success, *flavor is the type of thread state information returned in new_state.
    //
    // On entry, old_state is a pointer to the thread state information.  It's type 
    // is specified by *flavor.  For example, if *flavor is x86_THREAD_STATE32, you
    // can cast this to i386_thread_state_t and access the fields of that structure. 
    //
    // old_stateCnt is the size, in units of natural_t, of the thread state 
    // information supplied in old_state.  This size is determined by the flavour.  
    // For example, if *flavor is x86_THREAD_STATE32, old_state is a pointer to a 
    // i386_thread_state_t and this value is x86_THREAD_STATE32_COUNT.
    //
    // On entry, new_state is a pointer to a buffer of determined by *new_stateCnt. 
    // The contents of the buffer are unspecified.  On error, the contents of the 
    // buffer are ignored.  On success, the contents of this buffer, along with the 
    // final values of *flavor and *new_stateCnt, are used to 'correct' the state 
    // of the thread that took the exception.  For example, if, on succes, *flavor 
    // is x86_THREAD_STATE32 then *new_stateCnt should be x86_THREAD_STATE32_COUNT 
    // and the buffer pointed to be new_state must be set up as a i386_thread_state_t 
    // structure containing the new state of the thread.
    //
    // On entry, *new_stateCnt is the size of the buffer pointed to by new_state, 
    // in units of natural_t.  This will always be at least THREAD_STATE_MAX 
    // for the architecture for which you are compiled.  On error, *new_stateCnt 
    // is ignored.  On success, *new_stateCnt is the size, again in units 
    // of natural_t, of the new thread state information placed in new_state buffer.
    //
    // The function result determines the disposition of the exception.  There are 
    // three possible outcomes:
    //
    // o Success -- You return KERN_SUCCESS to indicate that you've successfully 
    //   handled the exception.  In this case, the new thread state denoted by 
    //   *flavor, *new_stateCnt and the contents of the new_state buffer are 
    //   applied to the thread and the thread resumes execution.
    //
    // o Failure -- You return any error except MIG_NO_REPLY to indicate that 
    //   you have failed to handle the exception.  In this case the exception 
    //   is passed to the next handler in the chain.  For example, if you've 
    //   installed a handler on the thread's exception port, the exception will 
    //   propagate to the task's exception port (at this point CrashReporter 
    //   will generate a crash log) and, if it's not handled there, to the host 
    //   exception port.  If it's still not handled, it will hit BSD and be 
    //   redirected back to the process as a signal.
    //
    // o Deferral -- If you return MIG_NO_REPLY, mach_msg_server will not send 
    //   a reply message to the exception message.  This will, effectively, 
    //   defer processing of the exception forever.  The only way to continue 
    //   processing the exception, and continue execution of the thread, is to 
    //   send a reply to the message by other means.  This will be tricky. 
    //
  { 
    kern_return_t           result;
    int                     i;
    i386_thread_state_t *  state;
    
    // Print out some information about the exception.
    
    //fprintf(stderr, "catch_exception_raise_state_identity\n");
    //fprintf(stderr, "  exception_port = %#x\n", exception_port);
    //fprintf(stderr, "  exception      = %d\n", exception);
    //fprintf(stderr, "  thread         = 0x%x\n", thread);
    for (i = 0; i < codeCnt; i++) {
        //fprintf(stderr, "  code[%d]        = %#x\n", i, code[i]);
    }
    //fprintf(stderr, "  *flavor        = %d\n", *flavor);
    //fprintf(stderr, "  old_stateCnt   = %d\n", old_stateCnt);
    //fprintf(stderr, "  *new_stateCnt  = %d\n", *new_stateCnt);
    //fprintf(stderr, "  i386_THREAD_STATE_COUNT = %d\n", i386_THREAD_STATE_COUNT);
	//fprintf(stderr, "  x86_THREAD_STATE32_COUNT= %d\n", x86_THREAD_STATE32_COUNT);
	//fprintf(stderr, "  x86_THREAD_STATE_COUNT  = %d\n", x86_THREAD_STATE_COUNT);
	
    assert( old_stateCnt == i386_THREAD_STATE_COUNT );
    state = (i386_thread_state_t *) old_state;

    //fprintf(stderr, "  state->eip     = %#x\n", state->eip);
    
    // Decide whether to handle it or not.
    
    if (exception == EXC_BREAKPOINT) {
        i386_thread_state_t *  newState;

        // For breakpoint exceptions, we just continue execution past the breakpoint.
    
        // Copy the old state to the new state.
        
        assert( old_stateCnt <= *new_stateCnt );
        *new_stateCnt = old_stateCnt;
        // no need to modify *flavor
        newState = (i386_thread_state_t *) new_state;
        *newState     = *state;

	suspend_thread(thread);

	// set globals
	thread_id = thread;
	exception_code = exception;
	// determine if single step 
	if(state->eflags & EFLAGS_TRAP || code[0] == EXC_I386_SGL){   // the code[0] is if its a hardware breakpoint.  Windows expects those to be reported as a single step event
		exception_code = EXCEPTION_SINGLE_STEP;
	} 
	exception_at = state->eip - 1;   // Cause of the cc
        thread_state_flavor_t flavor = i386_EXCEPTION_STATE;
        mach_msg_type_number_t exc_state_count = i386_EXCEPTION_STATE_COUNT;
        i386_exception_state_t exc_state;
        thread_get_state(thread,flavor, (natural_t*)&exc_state, &exc_state_count);
        exception_ref = exc_state.faultvaddr;
		//fprintf(stderr, "Hit breakpoint at %x\n", exception_at);
        result = KERN_SUCCESS;

        //fprintf(stderr, "  continuing from catch_exception_raise\n");
    } else if (exception == EXC_BAD_ACCESS){
		// This is bad - or good :) //
		// set globals
		thread_id = thread;
		exception_code = exception;
		exception_at = state->eip;   
        thread_state_flavor_t flavor = i386_EXCEPTION_STATE;
        mach_msg_type_number_t exc_state_count = i386_EXCEPTION_STATE_COUNT;
        i386_exception_state_t exc_state;
        thread_get_state(thread,flavor, (natural_t*)&exc_state, &exc_state_count);
        exception_ref = exc_state.faultvaddr;
		result = KERN_SUCCESS;
	} else {

        // Other exceptions are SEP (somebody else's problem).

        result = KERN_FAILURE;

        //fprintf(stderr, "  passing the buck\n");
    }
    
    return result;
}

#define MAX_EXCEPTION_PORTS 16

static struct {
    mach_msg_type_number_t count;
    exception_mask_t      masks[MAX_EXCEPTION_PORTS];
    exception_handler_t   ports[MAX_EXCEPTION_PORTS];
    exception_behavior_t  behaviors[MAX_EXCEPTION_PORTS];
    thread_state_flavor_t flavors[MAX_EXCEPTION_PORTS];
} old_exc_ports;

mach_port_t init(int pid){
    mach_port_t *     exceptionPort = malloc(sizeof(mach_port_t));
    mach_port_t me;
	task_t targetTask;
    exception_mask_t  mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC | EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL;

    //fprintf(stderr, "Hello Cruel World!\n");
    //fprintf(stderr, "pid = %d\n", pid);
    
    // Create a port by allocating a receive right, and then create a send right 
    // accessible under the same name.

    me = mach_task_self();    
    mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, exceptionPort);
	mach_port_insert_right(me, *exceptionPort, *exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    
	// get info for process
	if(task_for_pid(me, pid, &targetTask)!=KERN_SUCCESS){
		//printf("Task_for_pid");
		return 0;  // this is bad, probably bad pid.  returning 0 tells pydbg that attach failed.
	}
	
    /* get the old exception ports */
	task_get_exception_ports(targetTask, mask, old_exc_ports.masks, &old_exc_ports.count, old_exc_ports.ports, old_exc_ports.behaviors, old_exc_ports.flavors);
	
    /* set the new exception ports */
	task_set_exception_ports(targetTask, mask, *exceptionPort, EXCEPTION_STATE_IDENTITY, i386_THREAD_STATE);
//	task_set_exception_ports(targetTask, mask, exceptionPort, EXCEPTION_STATE_IDENTITY, MACHINE_THREAD_STATE);
//task_set_exception_ports(targetTask, mask, exceptionPort, EXCEPTION_DEFAULT, MACHINE_THREAD_STATE);
	return *exceptionPort;
}

/* These two structures contain some private kernel data. We don't need to
	struccess any of it so we don't bother defining a proper struct. The
	correct definitions are in the xnu source code. */    
struct {        
	mach_msg_header_t head;        
	char data[256];    
	} reply;    
			   
struct {        
	mach_msg_header_t head;        
	mach_msg_body_t msgh_body;        
	char data[1024];    
	} msg;

/* returns 1 if an event occured, 0 if it times out */
int my_msg_server(mach_port_t exception_port, int milliseconds, int *id, int *ec, unsigned int *eat, unsigned int *eref){
	mach_msg_return_t r;

	r = mach_msg(&msg.head,
		MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_TIMEOUT,
		0,
		sizeof(msg),
		exception_port,
		milliseconds,
		MACH_PORT_NULL);

	if(r == MACH_RCV_TIMED_OUT){
		return 0;
	} else if(r != MACH_MSG_SUCCESS){
		//printf("Got bad Mach message\n");
//		exit(-1);
	}

	/* Handle the message (calls catch_exception_raise) */
	if(!exc_server(&msg.head,&reply.head)){
		//printf("exc_server error\n");
//		exit(-1);
	}

	*id = thread_id;
	*ec = XToWinException(exception_code);
	*eat = exception_at;
	*eref = exception_ref;

	//printf("**************************************Got exception code %d\n", exception_code);
	
	r = mach_msg(
		&reply.head,
		MACH_SEND_MSG|MACH_SEND_TIMEOUT,
		reply.head.msgh_size,
		0,
		MACH_PORT_NULL,
		milliseconds,
		MACH_PORT_NULL);

	if(r == MACH_SEND_TIMED_OUT){
		return 0;
	} else if(r != MACH_MSG_SUCCESS){
		//printf("Got bad Mach message\n");
//		exit(-1);
	}

	return 1;
}
