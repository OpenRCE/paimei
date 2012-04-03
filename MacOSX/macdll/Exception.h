/*
 *  exception.h
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 12/15/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

int my_msg_server(mach_port_t exception_port, int milliseconds, int *id, int *ec, unsigned int *eat, unsigned int *eref);
void call_msg_server(mach_port_t exceptionPort);
mach_port_t init(int pid);
int XToWinException(int ec);