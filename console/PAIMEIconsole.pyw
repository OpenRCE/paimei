#!c:\python\python.exe

#
# PaiMei Console
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: PAIMEIconsole.pyw 193 2007-04-05 13:30:01Z cameron $
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

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import os
import socket
import cPickle
import sys
import wx
import wx.py as py

sys.path.append("modules")
sys.path.append("support")
sys.path.append("..")

try:
    import about

    missing_requirement = "MySQLdb"
    import mysql_connect_dialog

    missing_requirement = "PaiMei PyDbg"
    import pydbg_locale_dialog

    missing_requirement = "PaiMei Utilities"
    import udraw_connect_dialog

    import pydbg
    missing_requirement = False
except:
    pass

# this is the top most handle for accessing the entire console from the shell.
class __paimei__:
    pass

p = paimei = __paimei__()


########################################################################################################################
class persistant_state:
    '''
    This shell class is used to serial / unserialize persistant data to / from disk.
    '''

    username       = None
    pydbg_host     = None
    pydbg_port     = None
    mysql_host     = None
    mysql_username = None
    mysql_password = None
    udraw_host     = None
    udraw_port     = None


########################################################################################################################
class PAIMEIapp (wx.App):
    '''
    The top level wx class that is instantiated.
    '''

    def OnInit (self):
        wx.InitAllImageHandlers()

        splash = PAIMEIsplash()
        splash.Show()

        return True


########################################################################################################################
class PAIMEIsplash (wx.SplashScreen):
    '''
    Instantiated from PAIMEIapp, simply displays a splash screen and proceeds with creating the main frame
    (PAIMEIframe).
    '''

    def __init__ (self):
        bmp = wx.Image("images/splash.png").ConvertToBitmap()
        opt = wx.SPLASH_CENTRE_ON_SCREEN | wx.SPLASH_TIMEOUT

        wx.SplashScreen.__init__(self, bmp, opt, 2000, None, -1)

        self.Bind(wx.EVT_CLOSE, self.splash_finished)


    def splash_finished(self, evt):
        '''
        This routine is called once the splash screen has timed out.
        '''

        self.Hide()

        if missing_requirement:
            dlg = wx.MessageDialog(None,
                                   "Required module missing: %s\nRun the __install_requirements.py script." % missing_requirement,
                                   "Initialization Failed",
                                   wx.OK | wx.ICON_ERROR)
            dlg.ShowModal()
            dlg.Destroy()
            sys.exit(1)

        frame = PAIMEIframe(parent=None, title="PAIMEIconsole")
        frame.Maximize(True)
        frame.Show(True)
        evt.Skip()


########################################################################################################################
class PAIMEIframe (wx.Frame):
    '''
    Instantiated from PAIMEIsplash, this is the main frame of the PAIMEIconsole. A menu, status bar and custom listbook
    (PAIMEIlistbook) are created and compromise the general layout of the application. This class also defines dialog
    boxes to handle the menu events.
    '''

    documented_properties = {
        "paimei"               : "Top most handle under which every other attribute is accessible. A shortcut to this variable is available through 'p'.",
        ".main_frame"          : "Handle to main frame. Every component in the console is accessible under this variable.",
        ".current_module"      : "Handle to list book page of the currently activated module.",
        ".main_frame.mysql"    : "Handle to MySQL connection.",
        ".main_frame.pydbg"    : "Handle to PyDbg, customized by locale. You should not directly modify this variable, instead use copy.copy() to obtain a local PyDbg object.",
        ".main_frame.udraw"    : "Handle to uDraw(Graph) connector.",
        ".main_frame.modules"  : "Dictionary of currently loaded PaiMei modules.",
        ".main_frame.cwd"      : "Top level working directory of the PaiMei console (the directory containg PAIMEIconsole.pyw).",
        ".main_frame.username" : "Current console username.",
    }

    username       = None
    mysql          = None
    mysql_host     = None
    mysql_username = None
    mysql_password = None
    pydbg          = None
    pydbg_host     = None
    pydbg_port     = None
    udraw          = None
    udraw_host     = None
    udraw_port     = None
    modules        = {}
    cwd            = os.getcwd()

    def __init__ (self, *args, **kwds):
        global paimei
        paimei.main_frame = self

        self.pydbg = pydbg.pydbg()

        # restore stored connection options if available.
        try:
            fh = open(".options", "rb")
            ps = cPickle.loads(fh.read())
            fh.close()

            self.username       = ps.username
            self.mysql_host     = ps.mysql_host
            self.mysql_username = ps.mysql_username
            self.mysql_password = ps.mysql_password
            self.pydbg_host     = ps.pydbg_host
            self.pydbg_port     = ps.pydbg_port
            self.udraw_host     = ps.udraw_host
            self.udraw_port     = ps.udraw_port
        except:
            pass

        # documentation help choices.
        self.docs_modules_choices    = []
        self.docs_properties_choices = {}
        self.selected_module         = None

        self.parent = kwds["parent"]
        self.title  = kwds["title"]

        wx.Frame.__init__(self, self.parent, -1, self.title)
        self.CenterOnScreen()

        # set program icon.
        self.SetIcon(wx.Icon(self.cwd + "/images/paimei.ico", wx.BITMAP_TYPE_ICO))

        # instantiate and set the status bar.
        self.status_bar = PAIMEIstatusbar(parent=self)
        self.SetStatusBar(self.status_bar)

        # if the username was restored, show that in the status bar.
        self.status_bar.SetStatusText("User: %s" % self.username, 5)

        connect_menu = wx.Menu()
        connect_menu.Append(101, "&MySQL Connect",        "Connect to MySQL server.")
        connect_menu.Append(102, "&PyDbg Locale",         "Set PyDbg locale.")
        connect_menu.Append(103, "&Set Username",         "Tell PaiMei who you are.")
        connect_menu.Append(104, "&uDraw(Graph) Connect", "Connect to uDraw(Graph) server.")
        connect_menu.AppendSeparator()
        connect_menu.Append(105, "Save &Options",         "Save connection settings and automatically restore them on load.")
        connect_menu.Append(106, "&Restore Connections",  "Restore connections from saved settings.")

        advanced_menu = wx.Menu()
        advanced_menu.Append(201, "Clear Log",            "Clear the current modules log.")
        advanced_menu.Append(202, "Toggle Python &Shell", "Toggle interactive Python shell.")

        help_menu = wx.Menu()
        help_menu.Append(901, "&About", "About PAIMEIconsole.")

        self.menu = wx.MenuBar()
        self.menu.Append(connect_menu,  "&Connections")
        self.menu.Append(advanced_menu, "&Advanced")
        self.menu.Append(help_menu,     "&Help")

        self.SetMenuBar(self.menu)

        # set a handler for when menu items are highlighted.
        self.Bind(wx.EVT_MENU_HIGHLIGHT_ALL, self.OnMenuHighlight)

        # menu events.
        self.Bind(wx.EVT_MENU, self.OnMenuMySQLConnect,       id=101)
        self.Bind(wx.EVT_MENU, self.OnMenuPyDbgLocale,        id=102)
        self.Bind(wx.EVT_MENU, self.OnMenuSetUsername,        id=103)
        self.Bind(wx.EVT_MENU, self.OnMenuUDrawConnect,       id=104)
        self.Bind(wx.EVT_MENU, self.OnMenuSaveOptions,        id=105)
        self.Bind(wx.EVT_MENU, self.OnMenuRestoreConnections, id=106)
        self.Bind(wx.EVT_MENU, self.OnMenuClearLog,           id=201)
        self.Bind(wx.EVT_MENU, self.OnMenuPythonShell,        id=202)
        self.Bind(wx.EVT_MENU, self.OnMenuAbout,              id=901)

        # splitter stuff.
        self.splitter     = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER|wx.SP_PERMIT_UNSPLIT)
        self.shell_window = wx.Panel(self.splitter, -1)
        self.lbook_window = wx.Panel(self.splitter, -1)

        # create the listbook before the rest of the controls.
        self.lbook = PAIMEIlistbook(parent=self.lbook_window, top=self)

        # fill the doc controls.
        module_keys = self.modules.keys()
        module_keys.sort()

        # add the top-level variables to the doc control.
        self.docs_modules_choices.append("PaiMei")
        self.docs_properties_choices["PaiMei"] = {}
        for key, var in self.documented_properties.items():
            self.docs_properties_choices["PaiMei"][key] = var

        # step through the loaded modules, and add the documented variables to the doc control.
        for mod in module_keys:
            module = self.modules[mod]
            if hasattr(module, "documented_properties"):
                self.docs_modules_choices.append(mod)
                self.docs_properties_choices[mod] = {}

                for key, var in module.documented_properties.items():
                    self.docs_properties_choices[mod][key] = var

        # create the rest of the controls.
        self.pysh                  = py.shell.Shell(self.shell_window, -1, introText="")
        self.modules_staticbox     = wx.StaticBox(self.shell_window, -1, "Modules")
        self.variables_staticbox   = wx.StaticBox(self.shell_window, -1, "Attributes and Functions")
        self.description_staticbox = wx.StaticBox(self.shell_window, -1, "Description")
        self.docs_modules          = wx.Choice(self.shell_window, -1, choices=self.docs_modules_choices)
        self.docs_properties       = PShellVariableList(self.shell_window, -1, choices=[], top=self)
        self.docs_description      = wx.TextCtrl(self.shell_window, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)

        # bindings.
        self.Bind(wx.EVT_CHOICE, self.OnModuleSelected, self.docs_modules)

        # sizers.
        self.overall     = wx.BoxSizer(wx.VERTICAL)
        self.shell_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.shell_docs  = wx.BoxSizer(wx.VERTICAL)
        self.lbook_sizer = wx.BoxSizer(wx.HORIZONTAL)

        # layout.
        description_border = wx.StaticBoxSizer(self.description_staticbox, wx.HORIZONTAL)
        variables_border = wx.StaticBoxSizer(self.variables_staticbox, wx.HORIZONTAL)
        modules_border = wx.StaticBoxSizer(self.modules_staticbox, wx.HORIZONTAL)
        description_border.Add(self.docs_description, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        variables_border.Add(self.docs_properties, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        modules_border.Add(self.docs_modules, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.lbook_sizer.Add(self.lbook, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.lbook_window.SetAutoLayout(True)
        self.lbook_window.SetSizer(self.lbook_sizer)
        self.lbook_sizer.Fit(self.lbook_window)
        self.lbook_sizer.SetSizeHints(self.lbook_window)
        self.shell_sizer.Add(self.pysh, 3, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.shell_docs.Add(modules_border, 0, wx.EXPAND, 0)
        self.shell_docs.Add(variables_border, 1, wx.EXPAND, 0)
        self.shell_docs.Add(description_border, 1, wx.EXPAND, 0)
        self.shell_sizer.Add(self.shell_docs, 1, wx.EXPAND, 0)
        self.shell_window.SetAutoLayout(True)
        self.shell_window.SetSizer(self.shell_sizer)
        self.shell_sizer.Fit(self.shell_window)
        self.shell_sizer.SetSizeHints(self.shell_window)
        self.splitter.SplitHorizontally(self.lbook_window, self.shell_window)

        # hide the shell by default.
        self.splitter.Unsplit(self.shell_window)

        self.overall.Add(self.splitter, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(self.overall)
        self.overall.Fit(self)
        self.overall.SetSizeHints(self)
        self.Layout()

        event = wx.SizeEvent(self.GetSize())
        self.ProcessEvent(event)


    def OnMenuAbout (self, event):
        '''
        Event handler for the help\about menu item.
        '''

        dlg = about.about(parent=self)
        dlg.ShowModal()


    def OnMenuClearLog (self, event):
        '''
        Event handler for the advanced\clear log menu item.
        '''

        global paimei

        # ensure a page is selected.
        if not paimei.current_module:
            return

        # ensure the selected module has a log control.
        if not hasattr(paimei.current_module, "log"):
            return

        paimei.current_module.log.SetValue("")


    def OnMenuMySQLConnect (self, event):
        '''
        Event handler for the connections\mysql menu item.
        '''

        dlg = mysql_connect_dialog.mysql_connect_dialog(parent=self)
        dlg.ShowModal()


    def OnMenuPyDbgLocale (self, event):
        '''
        Event handler for the connections\pydbg menu item.
        '''

        dlg = pydbg_locale_dialog.pydbg_locale_dialog(parent=self)
        dlg.ShowModal()


    def OnMenuSetUsername (self, event):
        '''
        Event handler for the connections\set username menu item.
        '''

        if self.username: default = self.username
        else:             default = "Daniel-San"

        dlg = wx.TextEntryDialog(self, \
            "Tell PaiMei who you are. This username is used to tag various actions as belonging to you.", \
            "PaiMei wants to know your name...", \
            default)

        if dlg.ShowModal() == wx.ID_OK:
            self.username = dlg.GetValue()
            self.status_bar.SetStatusText("Welcome %s. Your training can now begin." % self.username, 0)
            self.status_bar.SetStatusText("User: %s" % self.username, 5)


    def OnMenuUDrawConnect (self, event):
        '''
        Event handler for the connections\udraw menu item.
        '''

        dlg = udraw_connect_dialog.udraw_connect_dialog(parent=self)
        dlg.ShowModal()


    def OnMenuHighlight (self, event):
        '''
        Describe the highlighted menu item in the status bar.
        '''

        id   = event.GetMenuId()
        item = self.GetMenuBar().FindItemById(id)

        if item:
            self.status_bar.SetStatusText(item.GetHelp(), 0)


    def OnMenuPythonShell (self, event):
        if self.splitter.IsSplit():
            self.splitter.Unsplit(self.shell_window)
        else:
            self.splitter.SplitHorizontally(self.lbook_window, self.shell_window)


    def OnMenuRestoreConnections (self, event):
        '''
        Event handler for the connections\restore connections menu item.
        '''

        busy = wx.BusyInfo("Restoring connections... please wait.")
        wx.Yield()

        # restore mysql connection.
        dlg = mysql_connect_dialog.mysql_connect_dialog(parent=self)
        dlg.mysql_connect(self.mysql_host, self.mysql_username, self.mysql_password)

        # restore pydbg locale
        dlg = pydbg_locale_dialog.pydbg_locale_dialog(parent=self)
        dlg.pydbg_set_locale(self.pydbg_host, self.pydbg_port)

        # restore udraw connection.
        dlg = udraw_connect_dialog.udraw_connect_dialog(parent=self)
        dlg.udraw_connect(self.udraw_host, self.udraw_port)


    def OnMenuSaveOptions (self, event):
        '''
        Event handler for the connections\save options menu item.
        '''

        fh = open(".options", "wb+")
        ps = persistant_state()

        ps.username       = self.username
        ps.mysql_host     = self.mysql_host
        ps.mysql_username = self.mysql_username
        ps.mysql_password = self.mysql_password
        ps.pydbg_host     = self.pydbg_host
        ps.pydbg_port     = self.pydbg_port
        ps.udraw_host     = self.udraw_host
        ps.udraw_port     = self.udraw_port

        fh.write(cPickle.dumps(ps))
        fh.close()

        self.status_bar.SetStatusText("Connection options saved and will be automatically restored.")


    def OnModuleSelected (self, event):
        '''
        Event handler for when a module is selected from the shell, module list dropdown.
        '''

        self.selected_module = event.GetString()

        variables = self.docs_properties_choices[self.selected_module].keys()
        variables.sort()

        self.docs_properties.Set(variables)


########################################################################################################################
class PAIMEIstatusbar (wx.StatusBar):
    '''
    Instantiated from PAIMEIframe, this class creates a custom status bar.

    Field 0 is for general framework use.
    Field 1 is for module use.
    Fields 2, 3, 4 and 5 display the established connections.
    '''

    def __init__ (self, *args, **kwds):
        self.parent = kwds["parent"]

        wx.StatusBar.__init__(self, self.parent, -1)

        self.SetFieldsCount(6)

        # set the fields to have relative widths.
        self.SetStatusWidths([-3, -4, -1, -1, -1, -1])

        # set the default status fields.
        self.SetStatusText("PaiMei ... Hayai!", 1)
        self.SetStatusText("MySQL: NONE", 2)
        self.SetStatusText("PyDbg: localhost", 3)
        self.SetStatusText("uDraw: NONE", 4)
        self.SetStatusText("User: NONE", 5)


########################################################################################################################
class PAIMEIlistbook (wx.Listbook):
    '''
    Instantiated from PAIMEIframe, this class establishes a chooser list on the left side of the screen and a variable
    and dynamically loaded frame on the right.
    '''

    def __init__ (self, *args, **kwds):
        global paimei

        self.parent = kwds["parent"]
        self.top    = kwds["top"]

        wx.Listbook.__init__(self, self.parent, -1, style=wx.LB_LEFT)

        image_list = wx.ImageList(96, 64)

        # load all available icons into the image list.
        for icon in os.listdir("images/icons"):
            if icon.endswith(".png"):
                bmp = wx.Image("images/icons/" + icon).ConvertToBitmap()
                image_list.Add(bmp)

        self.AssignImageList(image_list)

        image_id = 0
        for icon in os.listdir("images/icons"):
            if icon.endswith(".png"):
                try:
                    module       = icon.replace(".png", "")
                    module_short = module.replace("PAIMEI", "")

                    exec("from %s import *" % module)
                    exec("panel = %s(parent=self)" % module)

                    self.top.modules[module_short] = panel
                    exec("paimei.%s = panel" % module_short)

                    self.AddPage(panel, "", imageId=image_id)

                    # set the docs module as the default loaded page.
                    if module == "PAIMEIdocs":
                        self.SetSelection(image_id)
                        paimei.current_module = panel
                except:
                    import traceback
                    traceback.print_exc(file=sys.stdout)

                image_id += 1

        self.Bind(wx.EVT_LISTBOOK_PAGE_CHANGED, self.OnPageChanged)


    # update the currently selected listbook page.
    def OnPageChanged (self, event):
        global paimei

        paimei.current_module = self.GetPage(event.GetSelection())

        if hasattr(paimei.current_module, "_get_status"):
            self.top.status_bar.SetStatusText(paimei.current_module._get_status(), 1)
        else:
            self.top.status_bar.SetStatusText("PaiMei ... Hayai!", 1)


########################################################################################################################
class PShellVariableList (wx.ListBox):
    def __init__(self, *args, **kwds):
        self.top = kwds["top"]
        del kwds["top"]

        wx.ListBox.__init__(self, *args, **kwds)

        self.typed_text = ''

        self.Bind(wx.EVT_KEY_DOWN,       self.OnKey)
        self.Bind(wx.EVT_LISTBOX,        self.OnEvtListBox)
        self.Bind(wx.EVT_LISTBOX_DCLICK, self.OnEvtListBox)


    def FindPrefix (self, prefix):
        if prefix:
            prefix = prefix.lower()
            length = len(prefix)

            for x in range(self.GetCount()):
                text = self.GetString(x)
                text = text.lower()

                if text[:length] == prefix:
                    return x

        return -1


    def OnEvtListBox (self, event):
        description = self.top.docs_properties_choices[self.top.selected_module][event.GetString()]
        self.top.docs_description.SetValue(description)


    def OnKey (self, event):
        key = event.GetKeyCode()

        if key >= 32 and key <= 127:
            self.typed_text = self.typed_text + chr(key)
            item = self.FindPrefix(self.typed_text)

            if item != -1:
                self.SetSelection(item)

        # backspace removes one character and backs up
        elif key == wx.WXK_BACK:
            self.typed_text = self.typed_text[:-1]

            if not self.typed_text:
                self.SetSelection(0)
            else:
                item = self.FindPrefix(self.typed_text)

                if item != -1:
                    self.SetSelection(item)
        else:
            self.typed_text = ''
            event.Skip()


    def OnKeyDown (self, event):
        pass


########################################################################################################################

if __name__ == '__main__':
    wxapp = PAIMEIapp(True)
    wxapp.MainLoop()
