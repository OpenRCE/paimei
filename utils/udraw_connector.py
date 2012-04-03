#
# uDraw Connector
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: udraw_connector.py 193 2007-04-05 13:30:01Z cameron $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# Note: The majority of the uDraw functionality wrapper documentation was ripped directly from:
#
#    http://www.informatik.uni-bremen.de/uDrawGraph/en/index.html
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import socket

class udraw_connector:
    '''
    This class provides an abstracted interface for communicating with uDraw(Graph) when it is configured to listen on a
    TCP socket in server mode.

    @todo: Debug various broken routines, abstract more of the uDraw API.
    '''

    command_handlers = {}
    sock             = None

    ####################################################################################################################
    def __init__ (self, host="127.0.0.1", port=2542):
        '''
        '''

        self.command_handlers = {}
        self.sock             = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        # receive the initial notification message.
        self.sock.recv(8)

        self.log = lambda x: None


    ####################################################################################################################
    def change_element_color (self, element, id, color):
        '''
        This command is used to update the attributes of nodes and edges that exist in the current graph.
        '''

        command  = 'graph(change_attr(['
        command += '%s("%08x",[a("COLOR","#%06x")])'   % (element, id, color)
        command += ']))\n'
        self.send(command)


    ####################################################################################################################
    def focus_node (self, node_id, animated=True):
        '''
        Scrolls the visible part of the graph visualization to the node specified by "node_id".

        @todo: This routine is buggy. Appears to only want to work when being called after a call to
               change_element_color(), though the element color change will not actually work. Need to debug.
        '''

        if animated:
            command = 'special(focus_node_animated("%08x"))\n' % node_id
        else:
            command = 'special(focus_node("%08x"))\n' % node_id

        self.send(command)


    ####################################################################################################################
    def graph_new (self, graph):
        '''
        Sends a graph in term representation format to uDraw(Graph) for visualization.
        '''

        command  = 'graph(new_placed('
        command += graph.render_graph_udraw()
        command += '))\n'

        self.send(command)


    ####################################################################################################################
    def graph_update (self, graph):
        '''
        This command can be used to update the structure of the currently loaded graph.

        @todo: This routine is not behaving appropriately, need to debug.
        '''

        command  = "graph(mixed_update("
        command += graph.render_graph_udraw_update()
        command += "))\n"

        self.send(command)


    ####################################################################################################################
    def layout_improve_all (self):
        '''
        This command starts the layout algorithm to improve the visualization quality of the whole graph by reducing
        unnecessary edge crossings and edge bends.
        '''

        command = "menu(layout(improve_all))\n"
        self.send(command)

    ####################################################################################################################
    def message_loop (self, arg1, arg2):
        '''
        This routine should be threaded out. This routine will normally be called in the following fashion::

            thread.start_new_thread(udraw.message_loop, (None, None))

        The arguments to this routine are not currently used and will be ignored.
        '''

        while 1:
            try:
                from_server = self.sock.recv(1024)
                (command, args) = self.parse(from_server)

                if self.command_handlers.has_key(command):
                    self.command_handlers[command](self, args)
            except:
                # connection severed.
                break


    ####################################################################################################################
    def open_survey_view (self):
        '''
        Open a survey view showing the whole graph in a reduced scale.
        '''

        self.send("menu(view(open_survey_view))\n")


    ####################################################################################################################
    def parse (self, answer):
        '''
        '''

        answer = answer.rstrip("\r\n")
        self.log("raw: %s" % answer)

        # extract the answer type.
        command = answer.split('(')[0]
        args    = None

        # if the answer contains a list, extract and convert it into a native Python list.
        if answer.count("["):
            args = answer[answer.index('[')+1:answer.rindex(']')]

            if len(args):
                args = args.replace('"', '')
                args = args.split(',')
            else:
                args = None

        # otherwise, if there are "arguments", grab them as a string.
        elif answer.count("("):
            args = answer[answer.index('(')+2:answer.index(')')-1]

        self.log("parsed command: %s" % command)
        self.log("parsed args:    %s" % args)
        return (command, args)


    ####################################################################################################################
    def scale (self, parameter):
        '''
        Sets the scale to the given parameter which is a percent value that must be from 1 to 100.
        '''

        if parameter in ["full_scale", "full"]:
            parameter = "full_scale"

        elif parameter in ["fit_scale_to_window", "fit"]:
            parameter = fit_scale_to_window

        elif type(parameter) is int:
            parameter = "scale(%d)" % parameter

        else:
            return

        self.send("menu(view(%s))\n" % scale)


    ####################################################################################################################
    def send (self, data):
        '''
        '''

        msg  = "\n----- sending -------------------------------------------------------\n"
        msg += data + "\n"
        msg += "---------------------------------------------------------------------\n\n"

        self.log(msg)
        self.sock.send(data)


    ####################################################################################################################
    def set_command_handler (self, command, callback_func):
        '''
        Set a callback for the specified command. The prototype of the callback routines is::

            func (udraw_connector, args)

        You can register a callback for any command received from the udraw server.

        @type  command:        String
        @param command:        Command string
        @type  callback_func:  Function
        @param callback_func:  Function to call when specified exception code is caught.
        '''

        self.command_handlers[command] = callback_func


    ####################################################################################################################
    def window_background (self, bg):
        '''
        Sets the background of the base window to the color specified by parameter bg. This is a RGB value like
        "#0f331e" in the same format as used for command-line option -graphbg.
        '''

        command = 'window(background("%s"))' % bg
        self.send(command)


    ####################################################################################################################
    def window_status (self, msg):
        '''
        Displays a message in the right footer area of the base window.
        '''

        command = 'window(show_status("%s"))' % msg
        self.send(command)


    ####################################################################################################################
    def window_title (self, msg):
        '''
        Sets the title of the base window to msg.
        '''

        command = 'window(title("%s"))' % msg
        self.send(command)