/*
    PaiMei Connector - Header File
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

#ifndef __OLLY_PAIMEI_CONNECTOR_H__
#define __OLLY_PAIMEI_CONNECTOR_H__

#undef  DEBUG
#define PLUGIN_NAME "PaiMei Connector"

//
// global variables.
//

HINSTANCE hinst;                        // DLL instance
HWND      hwmain;                       // handle of main OllyDbg window
SOCKET    connection = NULL;

//
// function prototypes.
//

void paimei_connect       (void);
void paimei_xmit_location (t_dump *);

#endif