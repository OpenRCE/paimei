#!c:\python\python.exe

#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: pydbg_server.py 194 2007-04-05 15:31:53Z cameron $
#

'''
@author:       Pedram Amini
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import socket
import sys
import threading
import cPickle
import getopt

from pydbg import *
from pydbg.defines import *

# null either of these by setting to lambda x: None
err = lambda msg: sys.stderr.write("[!] " + msg + "\n") or sys.exit(1)
log = lambda msg: sys.stdout.write("[*] " + msg + "\n")


########################################################################################################################


class pydbg_server_thread (threading.Thread):
    def __init__ (self, client, client_address):
        threading.Thread.__init__(self)
        self.client         = client
        self.client_address = client_address
        self.pydbg          = pydbg(cs=True)
        self.connected      = True


    def callback_handler_wrapper (self, pydbg):
        try:
            # non client/server access to dbg/context are done via member variables. in client/server mode however, we
            # must excplicity pass these back to the client.
            self.pickle_send(("callback", pydbg.dbg, pydbg.context))
        except:
            return DBG_CONTINUE

        # enter a read loop, exiting when the client sends the "DONE" moniker.
        while 1:
            try:
                pickled = self.pickle_recv()
            except:
                return DBG_CONTINUE

            # XXX - this try except block should not be needed. look into the cause of why there is an out of order
            #       recv at some later point.
            try:
                (method, (args, kwargs)) = pickled
            except:
                break

            ret_message = False

            # client is done handling the exception.
            if method == "**DONE**":
                return args

            else:
                # resolve a pointer to the requested method.
                method_pointer = None

                try:
                    exec("method_pointer = self.pydbg.%s" % method)
                except:
                    pass

                if method_pointer:
                    try:
                        ret_message = method_pointer(*args, **kwargs)
                    except pdx, x:
                        ret_message = ("exception", x.__str__())

            try:
                self.pickle_send(ret_message)
            except:
                return DBG_CTONINUE


    def pickle_recv (self):
        try:
            length   = long(self.client.recv(4), 16)
            received = self.client.recv(length)

            return cPickle.loads(received)
        except:
            log("connection severed to %s:%d" % (self.client_address[0], self.client_address[1]))
            self.connected = False
            self.pydbg.set_debugger_active(False)
            raise Exception


    def pickle_send (self, data):
        print "sending", data
        data = cPickle.dumps(data)

        try:
            self.client.send("%04x" % len(data))
            self.client.send(data)
        except:
            log("connection severed to %s:%d" % (self.client_address[0], self.client_address[1]))
            self.connected = False
            self.pydbg.set_debugger_active(False)
            raise Exception


    def run (self):
        log("connection received from: %s:%d" % (self.client_address[0], self.client_address[1]))

        while self.connected:
            try:
                pickled = self.pickle_recv()
            except:
                break

            # XXX - this try except block should not be needed. look into the cause of why there is an out of order
            #       recv at some later point.
            try:
                (method, (args, kwargs)) = pickled
                print method, args, kwargs
            except:
                continue

            ret_message = False

            # if client requested the set_callback method.
            if method == "set_callback":
                self.pydbg.set_callback(args, self.callback_handler_wrapper)
                ret_message = True

            else:
                # resolve a pointer to the requested method.
                method_pointer = None
                try:
                    exec("method_pointer = self.pydbg.%s" % method)
                except:
                    pass

                if method_pointer:
                    try:
                        ret_message = method_pointer(*args, **kwargs)
                    except pdx, x:
                        ret_message = ("exception", x.__str__())

            try:
                self.pickle_send(ret_message)
            except:
                break


########################################################################################################################


# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:p:", ["host=","port="])
except getopt.GetoptError:
    err(USAGE)

host = "0.0.0.0"
port = 7373

for o, a in opts:
    if o in ("-h", "--host"): host = a
    if o in ("-p", "--port"): port = int(a)

try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
except:
    sys.stderr.write("Unable to bind to %s:%d\n" % (host, port))
    sys.exit(1)

while 1:
    log("waiting for connection")

    (client, client_address) = server.accept()

    server_thread = pydbg_server_thread(client, client_address)

    try:
        server_thread.start()
    except:
        log("client disconnected")