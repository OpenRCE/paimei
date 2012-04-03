#!c:\python\python.exe

# $Id: __install_requirements.py 194 2007-04-05 15:31:53Z cameron $

import urllib
import os
import shutil

# globals.
downloaded = 0

########################################################################################################################
def urllib_hook (idx, slice, total):
    global downloaded

    downloaded += slice

    completed = int(float(downloaded) / float(total) * 100)

    if completed > 100:
        completed = 100

    print "\tdownloading ... %d%%\r" % completed,


def get_it (url, file_name):
    global downloaded

    downloaded = 0
    u = urllib.urlretrieve(url, reporthook=urllib_hook)
    print
    shutil.move(u[0], file_name)
    os.system("start " + file_name)

########################################################################################################################

try:
    print "looking for ctypes ...",
    import ctypes
    print "FOUND"
except:
    print "NOT FOUND"
    choice = raw_input("\tWant me to get it? ").lower()
    if choice.startswith("y"):
        get_it("http://superb-east.dl.sourceforge.net/sourceforge/ctypes/ctypes-0.9.9.6.win32-py2.4.exe", "installers/ctypes-0.9.9.6.win32-py2.4.exe")

try:
    print "looking for pydot ...",
    import pydot
    print "FOUND"
except:
    print "NOT FOUND"

try:
    print "looking for wxPython ...",
    import wx
    print "FOUND"
except:
    print "NOT FOUND"
    choice = raw_input("\tWant me to get it? ").lower()
    if choice.startswith("y"):
        get_it("http://umn.dl.sourceforge.net/sourceforge/wxpython/wxPython2.6-win32-ansi-2.6.3.2-py24.exe", "installers/wxPython2.6-win32-ansi-2.6.3.2-py24.exe")

try:
    print "looking for MySQLdb ...",
    import MySQLdb
    print "FOUND"
except:
    print "NOT FOUND"
    choice = raw_input("\tWant me to get it? ").lower()
    if choice.startswith("y"):
        get_it("http://superb-east.dl.sourceforge.net/sourceforge/mysql-python/MySQL-python.exe-1.2.1_p2.win32-py2.4.exe", "installers/MySQL-python.exe-1.2.1_p2.win32-py2.4.exe")

try:
    print "looking for GraphViz in default directory ...",
    fh = open("c:\\program files\\graphviz")
    close(fh)
except IOError, e:
    if e.errno == 2:
        print "NOT FOUND"
    else:
        print "FOUND"

try:
    print "looking for Oreas GDE in default directory ...",
    fh = open("c:\\program files\\govisual diagram editor")
    close(fh)
except IOError, e:
    if e.errno == 2:
        print "NOT FOUND"
        choice = raw_input("\tWant me to get it? ").lower()
        if choice.startswith("y"):
            get_it("http://www.oreas.com/download/get_gde_win.php", "installers/gde-win.exe")
    else:
        print "FOUND"

try:
    print "looking for uDraw(Graph) in default directory ...",
    fh = open("c:\\program files\\udraw(graph)")
    close(fh)
except IOError, e:
    if e.errno == 2:
        print "NOT FOUND"
        choice = raw_input("\tWant me to get it? ").lower()
        if choice.startswith("y"):
            get_it("http://www.informatik.uni-bremen.de/uDrawGraph/download/uDrawGraph-3.1.1-0-win32-en.exe", "installers/uDrawGraph-3.1.1-0-win32-en.exe")
    else:
        print "FOUND"

try:
    print "looking for PaiMei -> PyDbg ...",
    import pydbg
    print "FOUND"
except:
    print "NOT FOUND"

try:
    print "looking for PaiMei -> PIDA ...",
    import pida
    print "FOUND"
except:
    print "NOT FOUND"

try:
    print "looking for PaiMei -> pGRAPH ...",
    import pgraph
    print "FOUND"
except:
    print "NOT FOUND"

try:
    print "looking for PaiMei -> Utilities ...",
    import utils
    print "FOUND"
except:
    print "NOT FOUND"

choice = raw_input("\nInstall PaiMei framework libraries to Python site packages? ").lower()
if choice.startswith("y"):
    os.system("start installers/PaiMei-1.1.win32.exe")

print "\nRun __setup_mysql.py to setup database and complete installation. Then run console\PAIMEIconsole.py"

raw_input("\nHit enter to exit installer.")