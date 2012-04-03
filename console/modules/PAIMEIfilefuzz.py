#
# Paimei File Fuzzing Module
# Copyright (C) 2006 Cody Pierce <cpierce@tippingpoint.com>
#
# $Id: PAIMEIfilefuzz.py 228 2007-10-22 20:14:10Z cody $
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
@author:       Cody Pierce
@license:      GNU General Public License 2.0 or later
@contact:      cpierce@tippingpoint.com
@organization: www.tippingpoint.com
'''

import sys, os, thread, time, datetime, copy, struct, smtplib, shutil
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

try:
    import win32api, win32con
    dynamic = True
except:
    dynamic = False
    
import wx
import wx.lib.filebrowsebutton as filebrowse
import wx.lib.newevent

import utils
from pydbg import *
from pydbg.defines import *

(ThreadEventUpdate, EVT_THREAD_UPDATE) = wx.lib.newevent.NewEvent()
(ThreadEventLog, EVT_THREAD_LOG) = wx.lib.newevent.NewEvent()
(ThreadEventEnd, EVT_THREAD_END) = wx.lib.newevent.NewEvent()

#import _PAIMEIfilefuzz

class TestCase:
    def __init__(self, main_window, program_name, timeout, file_list):
        self.main_window = main_window
        self.program_name = program_name
        self.program_type = ""
        self.program_cache = {}
        self.crash_dir = self.main_window.destination + '\\' + 'crashes'
        self.timeout = timeout
        self.file_list = file_list
        self.pydbg = ""
        self.stats = {}
        self.running = False
        self.paused = False
        self.current_pos = 0
        self.current_file = ""
        
        self.first_chance = self.main_window.first_chance
        self.show_window = self.main_window.show_window
        
        # Handles our email settings
        self.email_on = self.main_window.email_on
        self.email_to = self.main_window.email_to
        self.email_from = self.main_window.email_from
        self.email_server = self.main_window.email_server
        
    def Start(self):
        if not self.program_name and dynamic:
            evt = ThreadEventLog(msg = "Trying to dynamically do program launching")
            wx.PostEvent(self.main_window, evt)
            
            self.program_type = "Dynamic"
        else:
            self.program_type = "Static"
        
        self.running = True
               
        try:
            thread.start_new_thread(self.Run, ())
        except:
            evt = ThreadEventLog(msg = "Problem Starting Thread")
            wx.PostEvent(self.main_window, evt)
            self.End(-1)
    
    def Pause(self):
        self.paused = True
    
    def UnPause(self):
        self.paused = False
                
    def Stop(self):
        self.running = False

    def End(self, rc):
        self.rc = rc
        
        try:
            self.pydbg.terminate_process()
        except:
            pass
                    
        evt = ThreadEventEnd()
        wx.PostEvent(self.main_window, evt)

        return self.rc

    def Run(self):
        self.stats["files_ran"] = self.main_window.files_ran
        self.stats["files_left"] = self.main_window.files_left
        self.stats["end_time"] = self.main_window.end_time
        self.stats["num_crashes"] = 0
        self.stats["num_read"] = 0
        self.stats["num_write"] = 0
        self.stats["last_crash_addr"] = 0x00000000
        
        for item in self.file_list:
            if not self.running:
                evt = ThreadEventLog(msg = "Fuzzer thread stopping")
                wx.PostEvent(self.main_window, evt)
                self.End(-1)
                break
            
            if self.paused:
                evt = ThreadEventLog(msg = "Fuzzer thread paused")
                wx.PostEvent(self.main_window, evt)    
                
                while self.paused:
                    time.sleep(1)
            
            for key in item.keys():
                dbg = pydbg()
                
                self.current_pos = key
                self.current_file = item[key]

                evt = ThreadEventUpdate(pos = self.current_pos, stats = self.stats)
                wx.PostEvent(self.main_window, evt)
                
                # Run pydbg shit
                dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.ExceptionHandler)
                dbg.set_callback(EXCEPTION_GUARD_PAGE, self.GuardHandler)

                if self.program_type == "Dynamic":
                    extension = "." + self.current_file.split(".")[-1]
                    
                    evt = ThreadEventLog(msg = "Checking extension %s" % extension)
                    wx.PostEvent(self.main_window, evt)
                    
                    if self.program_cache.has_key(extension):
                        command = self.program_cache[extension]
                    else:
                        command = self.get_handler(extension, self.current_file)
                        self.program_cache[extension] = command
                    
                    if not command:
                        evt = ThreadEventLog(msg = "Couldnt find proper handler.")
                        wx.PostEvent(self.main_window, evt)
                        
                        continue
                    else:
                        try:
                            dbg.load(command, "\"" + self.current_file + "\"", show_window=self.show_window)
                        except pdx, x:
                            evt = ThreadEventLog(msg = "Problem Starting Program (%s): %s %s" % (x. __str__(), self.program_name, self.current_file))
                            wx.PostEvent(self.main_window, evt)
                else:   
                    try:
                        dbg.load(self.program_name, "\"" + self.current_file + "\"", show_window=self.show_window)
                    except pdx, x:
                        evt = ThreadEventLog(msg = "Problem Starting Program (%s): %s %s" % (x. __str__(), self.program_name, self.current_file))
                        wx.PostEvent(self.main_window, evt)
                    
                # Create watchdog thread
                try:
                    thread.start_new_thread(self.Watch, (dbg, self.current_file))
                except:
                    evt = ThreadEventLog(msg = "Problem Starting Thread")
                    wx.PostEvent(self.main_window, evt)
                    self.End(-1)
                
                #Continue execution
                try:
                    dbg.debug_event_loop()
                except pdx, x:
                    evt = ThreadEventLog(msg = "Problem in debug_Event_loop() (%s): %s %s" % (x.__str__(), self.program_name, self.current_file))
                    wx.PostEvent(self.main_window, evt)

                self.stats["files_ran"] += 1
                self.stats["files_left"] -= 1
                self.stats["end_time"] -= self.timeout
        
        # Finished fuzz run
        evt = ThreadEventUpdate(pos = key, stats = self.stats)
        wx.PostEvent(self.main_window, evt)

        evt = ThreadEventLog(msg = "Finished fuzzing!")
        wx.PostEvent(self.main_window, evt)
        
        self.main_window.msgbox("Finished fuzzing!")
        
        evt = ThreadEventLog(msg = "=" * 85)
        wx.PostEvent(self.main_window, evt)
        
        self.End(0)
        
    def Watch(self, pydbg, current_file):
        time.sleep(self.timeout)
        
        if pydbg.debugger_active:
	        try:
	            pydbg.terminate_process()
	        except pdx, x:
	            evt = ThreadEventLog(msg = "Couldnt Terminate Process (%s): %s %s" % (x.__str__(), self.program_name, current_file))
	            wx.PostEvent(self.main_window, evt)
	            
	            return 1
	        
	        return DBG_CONTINUE

    def GuardHandler(self, pydbg):
        evt = ThreadEventLog(msg = "[!] Guard page hit @ 0x%08x" % (pydbg.exception_address))
        wx.PostEvent(self.main_window, evt)
        
        return DBG_EXCEPTION_NOT_HANDLED
    
    def ExceptionHandler(self, pydbg):
        if pydbg.dbg.u.Exception.dwFirstChance and not self.first_chance:
            evt = ThreadEventLog(msg = "!!! Passing on first chance exception (%d) !!!" % pydbg.dbg.u.Exception.dwFirstChance)
            wx.PostEvent(self.main_window, evt)
            return DBG_EXCEPTION_NOT_HANDLED
        
        exception_address = pydbg.exception_address
        write_violation   = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        violation_address = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
        
        crash_bin = utils.crash_binning.crash_binning()
        crash_bin.record_crash(pydbg)

        # Lets move the file to our crashes directory
        if not os.path.isdir(self.crash_dir):
            try:
                os.mkdir(self.crash_dir)
            except:
                evt = ThreadEventLog(msg = "Could not create crash directory")
                wx.PostEvent(self.main_window, evt)
        
        try:
            shutil.copyfile(self.main_window.destination + '\\' + self.current_file, self.crash_dir + "\\" + self.current_file)
        except:
            evt = ThreadEventLog(msg = "Could not copy %s to %s" % (self.main_window.destination + '\\' + self.current_file, self.crash_dir + "\\" + self.current_file))
            wx.PostEvent(self.main_window, evt)
                
        logmessage = "\n\n[!] %s caused an access violation\n" % self.current_file
        logmessage += crash_bin.crash_synopsis()
        
        self.stats["num_crashes"] += 1
        self.stats["last_crash_addr"] = "%08x" % pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress
        
        if write_violation:
            self.stats["num_write"] += 1
        else:
            self.stats["num_read"] += 1
           
        evt = ThreadEventLog(msg = logmessage)
        wx.PostEvent(self.main_window, evt)
        time.sleep(self.timeout)
        
        evt = ThreadEventUpdate(pos = self.current_pos, stats = self.stats)
        wx.PostEvent(self.main_window, evt)
        
        if self.email_on:
            self.mail_exception(logmessage)
        
        try:
            pydbg.terminate_process()
        except pdx, x:
            evt = ThreadEventLog(msg = "Couldnt Terminate Process (%s): %s %s" % (x.__str__(), self.program_name, self.current_file))
            wx.PostEvent(self.main_window, evt)
        
        return DBG_CONTINUE

    def mail_exception(self, message):
        msg = MIMEMultipart()
        msg.attach(MIMEText(message))
        
        msg["Subject"] = "PAIMEI File Fuzz %s" % (self.current_file)
        msg["From"]    = self.email_from
        msg["To"]      = self.email_to
        msg["Date"]    = formatdate(localtime=True)
        
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(self.current_file,"rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"'
                       % os.path.basename(self.current_file))
        msg.attach(part)
        
        s = smtplib.SMTP()
        s.connect(self.email_server, 25)
        s.sendmail(self.email_from, self.email_to, msg.as_string())
        s.close()
        
        
    def get_handler(self, extension, current_file):
        handler = ""
        
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "%s" % extension)
        
        try:
            (handler, junk) = win32api.RegQueryValueEx(key, "")
        except:
            return ""
        
        command = ""
        
        try:
            key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "%s\\shell\\open\\command" % handler)
        except:
            return ""
        
        try:
            (command, junk) = win32api.RegQueryValueEx(key, "")
        except:
            return ""
        
        # This needs to be enhanced
        newcommand = command.rsplit(" ", 1)[0]
        
        return newcommand
        
#######################################################################################################################
class PAIMEIfilefuzz(wx.Panel):
    
    running              = False
    paused               = False
    first_chance         = True
    show_window          = True
    
    file_list_pos        = 0
    byte_length          = 0
    files_ran            = 0
    files_left           = 0
    num_crashes          = 0
    percent_crashes      = 0
    most_hit_addr        = 0x00000000
    most_hit_crashes     = 0
    last_crash_addr      = 0x00000000
    num_read             = 0
    num_write            = 0
    start_time           = 0
    running_time         = "00:00:00"
    end_time             = "00:00:00"
    logfile              = ""

    # This handles the setup of the email
    email_on             = True
    email_from           = "tsrt@tippingpoint.com"
    email_to             = "fuzz.results@gmail.com"
    email_server         = "usut001.3com.com"
    
    def __init__(self, *args, **kwds):
        # begin wxGlade: PAIMEIfilefuzz.__init__
        kwds["style"] = wx.TAB_TRAVERSAL
        wx.Panel.__init__(self, *args, **kwds)
        
        self.list_book  = kwds["parent"]             # handle to list book.
        self.pydbg = copy.copy(self.list_book.top.pydbg)      # handle to top most frame.
        
        self.main_splitter = wx.SplitterWindow(self, -1, style=wx.SP_3D|wx.SP_BORDER)
        
        self.log_window_pane = wx.Panel(self.main_splitter, -1)
        self.main_window_pane = wx.Panel(self.main_splitter, -1)
        
        self.setup_sizer_staticbox = wx.StaticBox(self.main_window_pane, -1, "Setup")
        self.setup_right_staticbox = wx.StaticBox(self.main_window_pane, -1, "Byte Modifications")

        self.file_inspector_staticbox = wx.StaticBox(self.main_window_pane, -1, "File Inspector")
        
        self.progress_sizer_staticbox = wx.StaticBox(self.main_window_pane, -1, "Progress")
        self.statistics_sizer_staticbox = wx.StaticBox(self.main_window_pane, -1, "Statistics")
        self.fuzz_sizer_staticbox = wx.StaticBox(self.main_window_pane, -1, "Fuzz")
        
        self.program_name_label = wx.StaticText(self.main_window_pane, -1, "Program Name")
        self.program_name_control = filebrowse.FileBrowseButtonWithHistory(self.main_window_pane, -1, size=(500, -1), labelText = "")
        self.program_name_control.SetHistory([])
        
        self.source_name_label = wx.StaticText(self.main_window_pane, -1, "Source File Name")
        self.source_name_control = filebrowse.FileBrowseButtonWithHistory(self.main_window_pane, -1, size=(500, -1), labelText = "")
        self.source_name_control.SetHistory([])
        
        self.destination_label = wx.StaticText(self.main_window_pane, -1, "Destination Directory")
        self.destination_control = filebrowse.DirBrowseButton(self.main_window_pane, -1, size=(500, -1), labelText = "")
        
        self.hex_label = wx.StaticText(self.main_window_pane, -1, "Hex Bytes")
        self.hex_control = wx.TextCtrl(self.main_window_pane, -1, "")
        
        self.start_label = wx.StaticText(self.main_window_pane, -1, "Range Start")
        self.start_control = wx.TextCtrl(self.main_window_pane, -1, "")
        self.start_control.SetMaxLength(7)
        
        self.end_label = wx.StaticText(self.main_window_pane, -1, "Range End")
        self.end_control = wx.TextCtrl(self.main_window_pane, -1, "")
        self.end_control.SetMaxLength(7)
        
        self.timeout_label = wx.StaticText(self.main_window_pane, -1, "Timeout (secs)")
        self.timer_control = wx.TextCtrl(self.main_window_pane, -1, "")
        self.timer_control.SetMaxLength(7)
        
        self.file_view_control = wx.TextCtrl(self.main_window_pane, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH2)
        
        self.file_list_box_control = wx.ListBox(self.main_window_pane, -1, choices=[], style=wx.LB_SINGLE)
        self.file_list_refresh_button = wx.Button(self.main_window_pane, -1, "Refresh List")
        
        self.generate_button_control = wx.Button(self.main_window_pane, -1, "Generate")
        self.run_button_control = wx.Button(self.main_window_pane, -1, "Run")
        self.stop_button_control = wx.Button(self.main_window_pane, -1, "Stop")
        
        self.stat_crashes_label = wx.StaticText(self.main_window_pane, -1, "# Crashes:")
        self.stat_crashes = wx.StaticText(self.main_window_pane, -1, "0 / 0%", style=wx.ALIGN_RIGHT)
        self.stat_num_read_label = wx.StaticText(self.main_window_pane, -1, "# Read Violations:")
        self.stat_num_read = wx.StaticText(self.main_window_pane, -1, "0 / 0%", style=wx.ALIGN_RIGHT)
        self.stat_num_write_label = wx.StaticText(self.main_window_pane, -1, "# Write Violations:")
        self.stat_num_write = wx.StaticText(self.main_window_pane, -1, "0 / 0%", style=wx.ALIGN_RIGHT)
        self.stat_running_time_label = wx.StaticText(self.main_window_pane, -1, "Running Time:")
        self.stat_running_time = wx.StaticText(self.main_window_pane, -1, "00:00:00", style=wx.ALIGN_RIGHT)
        self.stat_end_eta_label = wx.StaticText(self.main_window_pane, -1, "Estimated Completion:")
        self.stat_end_eta = wx.StaticText(self.main_window_pane, -1, "00:00:00", style=wx.ALIGN_RIGHT)
        self.stat_last_violaton_label = wx.StaticText(self.main_window_pane, -1, "Last Violation Address:")
        self.stat_last_violation = wx.StaticText(self.main_window_pane, -1, "N/A", style=wx.ALIGN_RIGHT)
        
        self.progress_text_label = wx.StaticText(self.main_window_pane, -1, "File 0 / 0")
        self.progress_gauge_control = wx.Gauge(self.main_window_pane, -1, 100, style=wx.GA_HORIZONTAL|wx.GA_SMOOTH)
        
        self.log = wx.TextCtrl(self.log_window_pane, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_LINEWRAP)

        self.__set_properties()
        self.__do_layout()

        #self.Bind(wx.EVT_BUTTON, self.OnHistory, self.history_button_control)
        #self.Bind(wx.EVT_BUTTON, self.OnSave, self.save_button_control)
        #self.Bind(wx.EVT_BUTTON, self.OnLoad, self.Load)
        self.Bind(wx.EVT_LISTBOX, self.OnFileList, self.file_list_box_control)
        self.Bind(wx.EVT_BUTTON, self.OnRefresh, self.file_list_refresh_button)
        self.Bind(wx.EVT_BUTTON, self.OnGenerate, self.generate_button_control)
        self.Bind(wx.EVT_BUTTON, self.OnRun, self.run_button_control)
        self.Bind(wx.EVT_BUTTON, self.OnStop, self.stop_button_control)
        
        # Thread events
        self.Bind(EVT_THREAD_UPDATE, self.OnThreadUpdate)
        self.Bind(EVT_THREAD_LOG, self.OnThreadLog)
        self.Bind(EVT_THREAD_END, self.OnThreadEnd)

        self.msg("PaiMei File Fuzz")
        self.msg("Module by Cody Pierce\n")

    def __set_properties(self):
        self.hex_control.SetMinSize((50, -1))
        self.hex_control.SetToolTipString("Byte to use in test case")
        self.start_control.SetMinSize((75, -1))
        self.start_control.SetToolTipString("Start byte location in test case")
        self.end_control.SetMinSize((75, -1))
        self.end_control.SetToolTipString("End byte location of test case")
        self.timer_control.SetMinSize((75, -1))
        self.timer_control.SetToolTipString("Number of seconds to wait before killing program")
        
        self.file_view_control.SetFont(wx.Font(9, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Terminal"))
        self.file_view_control.SetToolTipString("Hex dump of file")
        
        self.generate_button_control.SetToolTipString("Generate test cases based on options")
        self.run_button_control.SetToolTipString("Run the test cases in destination directory")
        self.stop_button_control.SetToolTipString("Stop running test cases")

        self.log.SetToolTipString("Log window of file fuzzer")
        self.log.SetFont(wx.Font(8, wx.MODERN, wx.NORMAL, wx.NORMAL, 0, "Lucida Console"))

    def __do_layout(self):
        overall_sizer = wx.BoxSizer(wx.HORIZONTAL)
        log_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        main_window_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        fuzz_sizer = wx.StaticBoxSizer(self.fuzz_sizer_staticbox, wx.VERTICAL)
        statistics_sizer = wx.StaticBoxSizer(self.statistics_sizer_staticbox, wx.HORIZONTAL)
        statistics_grid_sizer = wx.GridSizer(6, 2, 0, 0)
        setup_sizer = wx.StaticBoxSizer(self.setup_sizer_staticbox, wx.VERTICAL)
        progress_sizer = wx.StaticBoxSizer(self.progress_sizer_staticbox, wx.VERTICAL)
        
        file_inspector = wx.StaticBoxSizer(self.file_inspector_staticbox, wx.HORIZONTAL)
        
        setup_columns = wx.BoxSizer(wx.HORIZONTAL)
        setup_right = wx.StaticBoxSizer(self.setup_right_staticbox, wx.VERTICAL)
        setup_left = wx.BoxSizer(wx.VERTICAL)
        setup_left.Add(self.program_name_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_left.Add(self.program_name_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_left.Add(self.source_name_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_left.Add(self.source_name_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_left.Add(self.destination_label, 0, wx.ADJUST_MINSIZE, 0)
        setup_left.Add(self.destination_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_columns.Add(setup_left, 3, wx.EXPAND, 0)
        setup_right.Add(self.hex_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.hex_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.start_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.start_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.end_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.end_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.timeout_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_right.Add(self.timer_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_columns.Add(setup_right, 1, wx.EXPAND, 0)
        setup_sizer.Add(setup_columns, 1, wx.EXPAND, 0)
        file_inspector.Add(self.file_view_control, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_sizer.Add(file_inspector, 2, wx.EXPAND, 0)
        progress_sizer.Add(self.progress_text_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        progress_sizer.Add(self.progress_gauge_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        setup_sizer.Add(progress_sizer, 0, wx.EXPAND, 0)
        main_window_sizer.Add(setup_sizer, 2, wx.EXPAND, 0)
        fuzz_sizer.Add(self.file_list_box_control, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        fuzz_sizer.Add(self.file_list_refresh_button, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        fuzz_sizer.Add(self.generate_button_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        fuzz_sizer.Add(self.run_button_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        fuzz_sizer.Add(self.stop_button_control, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_crashes_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_crashes, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_num_read_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_num_read, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_num_write_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_num_write, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_running_time_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_running_time, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_end_eta_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_end_eta, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_last_violaton_label, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        statistics_grid_sizer.Add(self.stat_last_violation, 0, wx.EXPAND|wx.ALIGN_RIGHT|wx.ADJUST_MINSIZE, 0)
        statistics_sizer.Add(statistics_grid_sizer, 1, wx.EXPAND, 0)
        fuzz_sizer.Add(statistics_sizer, 1, wx.EXPAND, 0)
        main_window_sizer.Add(fuzz_sizer, 1, wx.EXPAND, 0)
        self.main_window_pane.SetAutoLayout(True)
        self.main_window_pane.SetSizer(main_window_sizer)
        main_window_sizer.Fit(self.main_window_pane)
        main_window_sizer.SetSizeHints(self.main_window_pane)
        log_window_sizer.Add(self.log, 1, wx.EXPAND, 0)
        self.log_window_pane.SetAutoLayout(True)
        self.log_window_pane.SetSizer(log_window_sizer)
        log_window_sizer.Fit(self.log_window_pane)
        log_window_sizer.SetSizeHints(self.log_window_pane)
        self.main_splitter.SplitHorizontally(self.main_window_pane, self.log_window_pane)
        overall_sizer.Add(self.main_splitter, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall_sizer)
        overall_sizer.Fit(self)
        overall_sizer.SetSizeHints(self)
        
        self.Layout()

    def OnStop(self, event):
        if self.running:
            self.running = False
            self.test_case_thread.Stop()
        else:
            event.Skip()
            
    def OnFileList(self, event):
        self.get_file_view()
        
    def OnRefresh(self, event):
        if self.running:
            return -1
            
        if self.destination_control.GetValue() == "":
            self.msgbox("Directory is not set")
            return -1
            
        self.destination = self.destination_control.GetValue()
        if not os.path.isdir(self.destination):
            self.msgbox("Destination directory does not exist")
            return -1
        
        while self.file_list_box_control.GetCount() > 0:
            self.file_list_box_control.Delete(0)

        filenames = os.listdir(self.destination)
        filenames.sort(cmp=self.numerifile)
        
        for file in filenames:
            self.file_list_box_control.Append(self.destination + "\\" + file)
        
        self.file_list_pos = self.file_list_box_control.GetCount() - 1
        
    def OnGenerate(self, event):
        if self.running:
            return -1

        if self.source_name_control.GetValue() == "" or self.destination_control.GetValue() == "" or self.hex_control.GetValue() == "":
           self.msgbox("Please enter all data!")
           return -1
           
        self.source_name = self.source_name_control.GetValue()
        if not os.path.isfile(self.source_name):
            self.msgbox("Source file does not exist")
            return -1
        
        # We store new history for control
        history = self.source_name_control.GetHistory()
        history.append(self.source_name)
        self.source_name_control.SetHistory(history)
        
        self.destination = self.destination_control.GetValue()
        if not os.path.isdir(self.destination):
            self.msgbox("Destination directory does not exist")
            return -1
            
        self.byte = self.hex_control.GetValue()
        
        if self.start_control.GetValue() == "":
            self.start = 0
        else:
            self.start = int(self.start_control.GetValue())
            
        if self.end_control.GetValue() == "":
            self.end = os.path.getsize(self.source_name)
        else:
            self.end = int(self.end_control.GetValue())
            
        if self.start > self.end:
            self.msgbox("Please make start < end jerk")
            return(-1)
        
        while self.file_list_box_control.GetCount() > 0:
            self.file_list_box_control.Delete(0)
            
        self.generate_files(self.source_name, self.destination, self.byte, self.start, self.end)

    def OnRun(self, event):
        if self.running and not self.paused:
            self.paused = True
            self.test_case_thread.Pause()
            self.run_button_control.SetLabel("UnPause")
            return -1
        elif self.running and self.paused:
            self.paused = False
            self.test_case_thread.UnPause()
            self.run_button_control.SetLabel("Pause")
            return -1
        
        if self.program_name_control.GetValue() == "" and not dynamic:
            self.msgbox("Please enter program name")
            return(-1)
            
        if self.timer_control.GetValue() == "" or self.timer_control.GetValue() <= 0:
            self.msgbox("Please enter all data!")
            return(-1)
         
        if self.file_list_pos < 0:
            self.msgbox("Nothing in file list")
            return(-1)
        
        self.running = True
        self.paused = False
        
        self.program_name = self.program_name_control.GetValue()
        
        # We store new history for control
        history = self.program_name_control.GetHistory()
        history.append(self.program_name)
        self.program_name_control.SetHistory(history)
        
        self.timeout = int(self.timer_control.GetValue())
        
        # This should be an option, but since we are moving to the new ui i wont waste my time
        if not self.logfile:
            self.logfile = open(self.destination + "\\" + "filefuzz.log", "a")
            
        self.msg("================================ %s ================================" % self.format_date())
        
        if self.start_control.GetValue() == "":
            self.start = 0
        else:
            self.start = int(self.start_control.GetValue())
            
        if self.end_control.GetValue() == "":
            self.end = self.file_list_pos + 1
        else:
            self.end = int(self.end_control.GetValue())
            
        if self.start > self.end:
            self.msgbox("Please make start < end jerk")
            return(-1)

        self.file_list = []
        
        #for count in xrange(self.start, self.end, 1):
        for count in range(self.file_list_box_control.GetCount()):
            testcase = {}
            testcase[count] = self.file_list_box_control.GetString(count)
            self.file_list.append(testcase)

        # Update stats
        self.files_ran = self.start
        self.files_left = self.end

        self.start_time = int(time.time())
        self.end_time = (self.end - self.start) * self.timeout

        self.update_stats()
        
        # Update gauge
        self.progress_text_label.SetLabel("File: %d / %d" % (self.start, self.end))
        
        self.test_case_thread = TestCase(self, self.program_name, self.timeout, self.file_list)
        self.test_case_thread.Start()
        self.run_button_control.SetLabel("Pause")
        self.msg("Started fuzz thread")
        
    def OnHistory(self, event):
        if self.running:
            return -1
            
        self.msg("Event handler `OnHistory' not implemented")
        event.Skip()

    def OnSave(self, event):
        if self.running:
            return -1
            
        self.msg("Event handler `OnSave' not implemented")
        event.Skip()

    def OnLoad(self, event):
        if self.running:
            return -1
            
        self.msg("Event handler `OnLoad' not implemented")
        event.Skip()
                
    def OnThreadUpdate(self, event):
        self.file_list_box_control.SetSelection(event.pos)
        self.get_file_view()
        
        # Update Stats
        self.files_ran = event.stats["files_ran"]
        self.files_left = event.stats["files_left"]
        self.num_crashes = event.stats["num_crashes"]
        self.num_read = event.stats["num_read"]
        self.num_write = event.stats["num_write"]
        self.end_time = event.stats["end_time"]
        self.last_crash_addr = event.stats["last_crash_addr"]
        
        self.update_stats()
        
        # Update Gauge
        self.progress_text_label.SetLabel("File: %d / %d" % (self.files_ran, self.end))
        self.progress_gauge_control.SetValue(int((float(self.files_ran) / float(self.end)) * 100))
        
    def OnThreadLog(self, event):
        self.msg(event.msg)
    
    def OnThreadEnd(self, event):
        self.running = False
        self.paused = False
        self.run_button_control.SetLabel("Run")
        self.msg("Thread has ended!")
            
    ####################################################################################################################
    def err (self, message):
        '''
        Write an error message to log window.
        '''

        self.log.AppendText("[!] %s\n" % message)


    ####################################################################################################################
    def msg (self, message):
        '''
        Write a log message to log window.
        '''

        if self.logfile:
            self.logfile.write("[*] %s\n" % message)
            self.logfile.flush()
        
        self.log.AppendText("[*] %s\n" % message)
    
    def msgbox(self, message):
        dlg = wx.MessageDialog(self, message,
                               '',
                               wx.OK | wx.ICON_INFORMATION
                               #wx.YES_NO | wx.NO_DEFAULT | wx.CANCEL | wx.ICON_INFORMATION
                               )
        dlg.ShowModal()
        dlg.Destroy()
        
    def update_stats(self):
        # Update stats
        
        # Crash shit
        self.stat_crashes.SetLabel("%-d / %-d%%" % (self.num_crashes, int((float(self.num_crashes) / float(self.end)) * 100)))
        self.stat_num_read.SetLabel("%d / %d%%" % (self.num_read, int((float(self.num_read) / float(self.end)) * 100)))
        self.stat_num_write.SetLabel("%d / %d%%" % (self.num_write, int((float(self.num_write) / float(self.end)) * 100)))
        self.stat_last_violation.SetLabel("0x%s" % self.last_crash_addr)
        
        # Time shit
        self.stat_running_time.SetLabel("%s" % self.seconds_strtime(int(time.time()) - self.start_time))
        self.stat_end_eta.SetLabel("%s" % self.seconds_strtime(self.end_time))

    def generate_files(self, source_name, destination, outbyte, start, end):
        '''
        Generates the test cases
        '''
        self.byte_length, rem = divmod(len(outbyte) - 2, 2)
        if rem:
            self.byte_length += 1
        
        current_file = 1
        
        # Update gauge
        self.progress_text_label.SetLabel("File: %d / %d" % (current_file, ((end - start) / self.byte_length) + 1))
        
        # Get progress bar range
        self.progress_gauge_control.SetValue(0)
        
        extension = source_name.split(".")[-1]
        infile = open(source_name, 'rb')
        
        contents = infile.read()
        
        for byte in xrange(start, end+1, self.byte_length):
            newcontents = ""
            
            newfile = str(byte) + "." + extension
            
            # Set the current file
            self.progress_text_label.SetLabel("File: %d / %d" % (current_file, ((end - start) / self.byte_length) + 1))
            
            # Open new file
            outfile = open(destination + "\\" + newfile, 'wb')
            
            # Write up to byte
            newcontents = contents[0:byte]
            # Write byte/s
            if self.byte_length <= 1:
                newcontents += struct.pack(">B", int(outbyte, 16))
            elif self.byte_length <= 2:
                newcontents += struct.pack(">H", int(outbyte, 16))
            elif self.byte_length <= 4:
                newcontents += struct.pack(">L", int(outbyte, 16))
            elif self.byte_length <= 8:
                newcontents += struct.pack(">Q", int(outbyte, 16))
            
            # Write from byte on
            newcontents += contents[byte+self.byte_length:]
            
            outfile.write(newcontents)
            outfile.close
            
            self.file_list_box_control.Append(destination + "\\" + newfile)
            self.progress_gauge_control.SetValue(int((float(current_file) / float(((end - start) / self.byte_length) + 1)) * 100))
            current_file += 1
                
        self.file_list_pos = self.file_list_box_control.GetCount() - 1
            
            
        infile.close()
        
        self.msg("File Generation Completed Successfully!")
            
    def run_fuzz(self, start, end):
        
        # Set static stats
        self.start_time = int(time.time())
        self.end_time = (end - start) * self.timeout
        for count in xrange(start, end, 1):    
       
            self.file_list_box_control.SetSelection(count)
            self.get_file_view()
            self.current_file_name = self.file_list_box_control.GetStringSelection()
            
            # Update gauge
            self.progress_text_label.SetLabel("File: %d / %d" % (count, self.file_list_pos))
            
            # Update stats
            self.stat_files_ran.SetLabel("%d" % count)
            self.stat_files_left.SetLabel("%d" % ((self.file_list_pos) - count))
            self.stat_running_time.SetLabel(self.seconds_strtime(int(time.time()) - self.start_time))
            self.stat_end_eta.SetLabel(self.seconds_strtime((end - count) * self.timeout))
            
            # Create thread
            test_case_thread = TestCase(self)
            test_case_thread.Start()
            test_case_thread.Join(self.timeout)

            wx.Yield()

            # Update gauge
            self.progress_gauge_control.SetValue(int((float(count) / float(self.file_list_pos)) * 100))
            
        # Update final gauges
        self.progress_text_label.SetLabel("File: %d / %d" % (0, 0))
        self.stat_running_time.SetLabel(self.seconds_strtime(int(time.time()) - self.start_time))
        self.stat_end_eta.SetLabel("00:00:00")
        self.progress_gauge_control.SetValue(0)
        
    def get_file_view(self):
        fullpath = self.file_list_box_control.GetStringSelection()

        if not os.path.isfile(fullpath):
            self.msg("File is not a file!")
            return -1
        
        try:
            filehandle = open(fullpath, 'rb')
        except:
            self.msg("Couldnt open %s" % fullpath)
            return -1
        
        try:
            filecontents = filehandle.read()
        except:
            self.msg("Couldnt read %s" % fullpath)
            
            filehandle.close()
            
            return -1
        
        try:    
            filehandle.close()
        except:
            self.msg("Couldnt close %s" % fullpath)
            return -1
        
        try:
            filename = os.path.basename(fullpath)
            filesize = os.path.getsize(fullpath)
            filebyte = int(filename.split(".")[0])
        except:
            self.msg("Error getting file stats!")
            return -1
        
        if filebyte < 256:
            start = 0
        else:
            start = filebyte - 256
        
        while start % 16 != 0:
            start -= 1
            
        if filebyte > filesize - 256:
            end = filesize
        else:
            end = filebyte + 256
        
        # Clear control
        self.file_view_control.Clear()
        
        counter = 0
        bytepos = 0
        length  = 0
        
        for filepos in xrange(start, end, 1):
            byte = filecontents[filepos]

            if counter == 0:
                self.file_view_control.AppendText("0x%08x: " % filepos,)
                counter += 1
            
            if filepos == filebyte or length > 0:
                bytepos = self.file_view_control.GetInsertionPoint()
                self.file_view_control.SetStyle(bytepos, bytepos, wx.TextAttr("RED", "WHITE"))
                
                if length != 0:
                    length = length - 1
                else:
                    length = self.byte_length - 1
            elif byte == "\x00":
                self.file_view_control.SetStyle(self.file_view_control.GetInsertionPoint(), self.file_view_control.GetInsertionPoint(), wx.TextAttr("GREY", "WHITE"))
            else:
                #self.file_view_control.SetStyle(-1, -1, self.file_view_control.GetDefaultStyle())
                self.file_view_control.SetStyle(-1, -1, wx.TextAttr("BLACK", "WHITE"))
                 
            if counter < 16:
                self.file_view_control.AppendText("0x%02x " % ord(byte),)
                counter += 1
            else:
                self.file_view_control.AppendText("0x%02x\n" % ord(byte))
                counter = 0

        self.file_view_control.ShowPosition(bytepos)
    
    def format_date(self):
        return time.strftime("%m/%d/%Y %H:%M:%S", time.gmtime())
        
    def seconds_strtime(self, seconds):
        hour = seconds / 3600   
        minutes = (seconds - (hour * 3600)) / 60
        seconds = (seconds - (hour * 3600) - (minutes * 60))

        return "%02d:%02d:%02d" % (hour, minutes, seconds)           
    
    def numerifile(self, x, y):
        try:
            x = int(x[:x.rfind(".")]) 
            y = int(y[:y.rfind(".")]) 
        except:
            return 1
            
        if   x  < y: return -1
        elif x == y: return 0
        else:        return 1