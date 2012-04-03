/*
    PaiMei Connector - Call Back Functions
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

//
// ollydbg call-back functions.
//

BOOL WINAPI DllEntryPoint (HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        hinst = hi;

    return TRUE;
}


int _export cdecl ODBG_Plugindata (char shortname[32])
{
    strcpy(shortname, "PaiMei Connector");
    return PLUGIN_VERSION;
}


int _export cdecl ODBG_Plugininit (int ollydbgversion, HWND hw, ulong *features)
{
    if (ollydbgversion < PLUGIN_VERSION)
        return -1;

    // keep a handle to the main OllyDbg window.
    hwmain = hw;

    olly_add_to_list(0, 0,  "PaiMei Connector Plug-in compiled on " __DATE__);
    olly_add_to_list(0, -1, "  Copyright (c) 2006 Pedram Amini <pedram.amini@gmail.com>");

    return 0;
}


void _export cdecl ODBG_Plugindestroy (void)
{
}


int _export cdecl ODBG_Pluginmenu (int origin, char data[4096], void *item)
{
    switch (origin)
    {
        case PM_MAIN:
            strcpy(data,
                   "0 Connect to Server,"
                   "1 Send Current Location|"
                   "2 Disconnect from Server|"
                   "9 About"
                  );
            return 1;
        case PM_DISASM:
        case PM_CPUDUMP:
            strcpy(data,
                   "PaiMei {"
                       "1 Send Current Location"
                   "}"
                  );
            return 1;
        default:
            break;
    }

    return 0;
}


void _export cdecl ODBG_Pluginaction (int origin, int action, void *item)
{
    t_dump *pd;
    pd = (t_dump *) item;

    switch (origin)
    {
        case PM_MAIN:
        case PM_DISASM:
        case PM_CPUDUMP:
            switch (action)
            {
                // connect to server
                case 0:
                    paimei_connect();
                    break;

                // send current location
                case 1:
                    paimei_xmit_location(pd);
                    break;

                // disconnect from server
                case 2:
                    closesocket(connection);
                    WSACleanup();
                    connection = NULL;
                    break;

                // about
                case 9:
                    MessageBox(hwmain,
                        "PaiMei Connector Plug-in\n\n"
                        "Copyright (c) 2006 Pedram Amini <pedram.amini@gmail.com>\n",
                        "About PaiMei Connector Plug-in",
                        MB_OK | MB_ICONINFORMATION);
                    break;
                
                default:
                    break;
            }
    }
}


int _export cdecl ODBG_Pluginshortcut(int origin, int ctrl, int alt, int shift, int key, void *item)
{
    t_dump *pd;
    
    pd = (t_dump *) item;

    switch (origin)
    {
        case PM_DISASM:

            if (key == 188 || key == 190 || key == 191)     // '<', '>', '/'
            {
                if (!connection)
                    paimei_connect();

			    // '<' = step into as well.
			    if (key == 188)
                    Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 0, VK_F7);
                
                // '>' = step over as well.
                if (key == 190)
                    Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 0, VK_F8);

                // transmit current location.
                paimei_xmit_location(pd);

                return 1;       // shortcut recognized.
            }
    }

    return 0;           // shortcut not recognized.
}