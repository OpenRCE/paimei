/*
    PaiMei OllyDbg Connector
    Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA
*/



#include "stdafx.h"
#include <stdio.h>

#include "olly_redefines.h"
#include "plugin.h"
#include "paimei_ollydbg_connector.h"
#include "olly_callbacks.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// connect to a paimei receiver.

void paimei_connect (void)
{
    hostent      *he;
    sockaddr_in  sin;
    in_addr      addr;
    WSADATA      wsa_data;

    char server[256];

    memset(server, 0, sizeof(server));
    strcpy(server, "127.0.0.1");

    // if we are already connected then to do nothing.
    if (connection)
        return;

    if (Gettext("PaiMei Server:", server, 0x00, NM_NONAME, FIXEDFONT) == -1)
        return;

    // initialize winsock.
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        olly_add_to_list(0, 1, "[!] "PLUGIN_NAME"> WSAStartup() failed.");
        return;
    }

    // confirm that the requested winsock version is supported.
    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
    {
        WSACleanup();
        olly_add_to_list(0, 1, PLUGIN_NAME"> Winsock version 2.2 not found.");
        return;
    }

    // if the provided server address is a hostname, then resolve it with gethostbyname().
    if (isalpha(server[0]))
    {
        if ((he = gethostbyname(server)) == NULL)
        {
            olly_add_to_list(0, 1, "[!] "PLUGIN_NAME"> Unable to resolve name: %s", server);
            return;
        }
    }
    // otherwise resolve the server address with gethostbyaddr().
    else
    {
        addr.s_addr = inet_addr(server);

        if ((he = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET)) == NULL)
        {
            olly_add_to_list(0, 1, "[!] "PLUGIN_NAME"> Unable to resolve address");
            return;
        }
    }

    // create a socket.
    if ((connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        WSACleanup();
        olly_add_to_list(0, 1, "[!] "PLUGIN_NAME"> Failed to create socket.");
        return;
    }

    // connect to the server.
    sin.sin_family = AF_INET;
    sin.sin_addr   = *((LPIN_ADDR)*he->h_addr_list);
    sin.sin_port   = htons(7033);

    if (connect(connection, (SOCKADDR *) &sin, sizeof(sin)) == SOCKET_ERROR)
    {
        WSACleanup();
        olly_add_to_list(0, 1, "[!] "PLUGIN_NAME"> Failed to connect to server.");
        return;
    }
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// send current location to paimei connector.

void paimei_xmit_location (t_dump *pd)
{
    t_module *tmod;
    char     buf[128];
    size_t   len;

    if (!connection)
    {
        olly_add_to_list(0, 1, "connect to paimei receiver first.");
        return;
    }

    if (!pd)
    {
        olly_add_to_list(0, 1, "no current item to xmit.");
        return;
    }

    tmod = olly_find_module(pd->sel0);
    
    // null terminate the short name.
    tmod->name[SHORTLEN] = 0;

    olly_add_to_list(0, 0, "%08x is in %s based at %08x", pd->sel0, tmod->name, tmod->base);

    sprintf(buf, "%s:%08x\n", tmod->name, pd->sel0 - tmod->base);
    len = strlen(buf);

    // connection to server successful.
    if (send(connection, buf, len, 0) != len)
    {
        closesocket(connection);
        WSACleanup();
        connection = NULL;
    }
}