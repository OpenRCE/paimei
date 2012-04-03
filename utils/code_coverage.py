#
# Code Coverage
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: code_coverage.py 193 2007-04-05 13:30:01Z cameron $
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

# we don't want to make mysql a mandatory module for the utils library.
try:    import MySQLdb
except: pass

import time
import zlib
import cPickle

class __code_coverage_struct__:
    eip         = 0x00000000
    tid         = 0
    num         = 0
    timestamp   = 0
    module      = ""
    base        = 0
    is_function = 0

    # registers and stack values.
    eax = ebx = ecx = edx = edi = esi = ebp = esp = esp_4 = esp_8 = esp_c = esp_10 = 0

    # register dereferences.
    eax_deref = ebx_deref = ecx_deref = edx_deref = edi_deref = esi_deref = ebp_deref = ""

    # stack dereferences.
    esp_deref = esp_4_deref = esp_8_deref = esp_c_deref = esp_10_deref = ""


class code_coverage:
    '''
    The purpose of this class is to provide an easy interface to keeping track of code coverage data. The Process
    Stalker utility for example relies on this class.

    @note: Contains hit list in self.hits.
    '''

    hits        = {}
    num         = 1
    heavy       = None
    mysql       = None
    main_module = "[MAIN]"

    ####################################################################################################################
    def __init__ (self, mysql=None, heavy=False):
        '''
        @type  heavy: Boolean
        @param heavy: (Optional, Def=False) Flag controlling whether or not to save context information at each point.
        '''

        self.hits        = {}
        self.num         = 1
        self.heavy       = heavy
        self.mysql       = mysql
        self.main_module = "[MAIN]"


    ####################################################################################################################
    def add (self, pydbg, is_function):
        '''
        Add the current context to the tracked code coverage.

        @type  pydbg:       PyDbg
        @param pydbg:       Debugger instance
        @type  is_function: Integer (bool 0/1)
        @param is_function: Flag whether or not the current hit occurred at the start of a function.

        @rtype:  code_coverage
        @return: self
        '''

        ccs = __code_coverage_struct__()

        # assume we hit inside the main module, unless we can find the specific module we hit in.
        module = self.main_module
        base   = 0

        # determine the module this hit occured in.
        mod32 = pydbg.addr_to_module(pydbg.context.Eip)

        if mod32:
            module = mod32.szModule.lower()
            base   = mod32.modBaseAddr

        ccs.eip         = pydbg.context.Eip
        ccs.tid         = pydbg.dbg.dwThreadId
        ccs.num         = self.num
        ccs.timestamp   = int(time.time())
        ccs.module      = module
        ccs.base        = base
        ccs.is_function = is_function

        context_list = pydbg.dump_context_list(stack_depth=4, print_dots=True)

        if self.heavy:
            ccs.eax    = pydbg.context.Eax
            ccs.ebx    = pydbg.context.Ebx
            ccs.ecx    = pydbg.context.Ecx
            ccs.edx    = pydbg.context.Edx
            ccs.edi    = pydbg.context.Edi
            ccs.esi    = pydbg.context.Esi
            ccs.ebp    = pydbg.context.Ebp
            ccs.esp    = pydbg.context.Esp
            ccs.esp_4  = context_list["esp+04"]["value"]
            ccs.esp_8  = context_list["esp+08"]["value"]
            ccs.esp_C  = context_list["esp+0c"]["value"]
            ccs.esp_10 = context_list["esp+10"]["value"]

            ccs.eax_deref    = context_list["eax"]
            ccs.ebx_deref    = context_list["ebx"]
            ccs.ecx_deref    = context_list["ecx"]
            ccs.edx_deref    = context_list["edx"]
            ccs.edi_deref    = context_list["edi"]
            ccs.esi_deref    = context_list["esi"]
            ccs.ebp_deref    = context_list["ebp"]
            ccs.esp_deref    = context_list["esp"]
            ccs.esp_4_deref  = context_list["esp+04"]["desc"]
            ccs.esp_8_deref  = context_list["esp+08"]["desc"]
            ccs.esp_c_deref  = context_list["esp+0c"]["desc"]
            ccs.esp_10_deref = context_list["esp+10"]["desc"]

        if not self.hits.has_key(ccs.eip):
            self.hits[ccs.eip] = []

        self.hits[ccs.eip].append(ccs)
        self.num += 1

        return self


    ####################################################################################################################
    def clear_mysql (self, target_id, tag_id):
        '''
        Removes all code coverage hits from target/tag id combination. Expects connection to database to already exist
        via self.mysql.

        @see: connect_mysql(), import_mysql(), export_mysql()

        @type  target_id: Integer
        @param target_id: Name of target currently monitoring code coverage of
        @type  tag_id:    Integer
        @param tag_id:    Name of this code coverage run

        @rtype:  code_coverage
        @return: self
        '''

        cursor = self.mysql.cursor()

        try:
            cursor.execute("DELETE FROM cc_hits WHERE target_id = '%d' AND tag_id = '%d'" % (target_id, tag_id))
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            print sql
            print

        cursor.close()
        return self


    ####################################################################################################################
    def connect_mysql (self, host, user, passwd):
        '''
        Establish a connection to a MySQL server. This must be called prior to export_mysql() or import_mysql().
        Alternatively, you can connect manually and set the self.mysql member variable.

        @see: export_mysql(), import_mysql()

        @type  host:      String
        @param host:      MySQL hostname or ip address
        @type  user:      String
        @param user:      MySQL username
        @type  passwd:    String
        @param passwd:    MySQL password

        @rtype:  code_coverage
        @return: self
        '''

        self.mysql = MySQLdb.connect(host=host, user=user, passwd=passwd, db="paimei")

        return self


    ####################################################################################################################
    def export_file (self, file_name):
        '''
        Dump the entire object structure to disk.

        @see: import_file()

        @type  file_name:   String
        @param file_name:   File name to export to

        @rtype:             code_coverage
        @return:            self
        '''

        fh = open(file_name, "wb+")
        fh.write(zlib.compress(cPickle.dumps(self, protocol=2)))
        fh.close()

        return self


    ####################################################################################################################
    def export_mysql (self, target_id, tag_id):
        '''
        Export code coverage data to MySQL. Expects connection to database to already exist via self.mysql.

        @see: clear_mysql(), connect_mysql(), import_mysql()

        @type  target_id: Integer
        @param target_id: Name of target currently monitoring code coverage of
        @type  tag_id:    Integer
        @param tag_id:    Name of this code coverage run

        @rtype:  code_coverage
        @return: self
        '''

        cursor = self.mysql.cursor()

        for hits in self.hits.values():
            for ccs in hits:
                sql  = "INSERT INTO cc_hits"
                sql += " SET target_id    = '%d'," % target_id
                sql += "     tag_id       = '%d'," % tag_id
                sql += "     num          = '%d'," % ccs.num
                sql += "     timestamp    = '%d'," % ccs.timestamp
                sql += "     eip          = '%d'," % ccs.eip
                sql += "     tid          = '%d'," % ccs.tid
                sql += "     eax          = '%d'," % ccs.eax
                sql += "     ebx          = '%d'," % ccs.ebx
                sql += "     ecx          = '%d'," % ccs.ecx
                sql += "     edx          = '%d'," % ccs.edx
                sql += "     edi          = '%d'," % ccs.edi
                sql += "     esi          = '%d'," % ccs.esi
                sql += "     ebp          = '%d'," % ccs.ebp
                sql += "     esp          = '%d'," % ccs.esp
                sql += "     esp_4        = '%d'," % ccs.esp_4
                sql += "     esp_8        = '%d'," % ccs.esp_8
                sql += "     esp_c        = '%d'," % ccs.esp_c
                sql += "     esp_10       = '%d'," % ccs.esp_10
                sql += "     eax_deref    = '%s'," % ccs.eax_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     ebx_deref    = '%s'," % ccs.ebx_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     ecx_deref    = '%s'," % ccs.ecx_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     edx_deref    = '%s'," % ccs.edx_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     edi_deref    = '%s'," % ccs.edi_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esi_deref    = '%s'," % ccs.esi_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     ebp_deref    = '%s'," % ccs.ebp_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esp_deref    = '%s'," % ccs.esp_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esp_4_deref  = '%s'," % ccs.esp_4_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esp_8_deref  = '%s'," % ccs.esp_8_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esp_c_deref  = '%s'," % ccs.esp_c_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     esp_10_deref = '%s'," % ccs.esp_10_deref.replace("\\", "\\\\").replace("'", "\\'")
                sql += "     is_function  = '%d'," % ccs.is_function
                sql += "     module       = '%s'," % ccs.module
                sql += "     base         = '%d' " % ccs.base

                try:
                    cursor.execute(sql)
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0], e.args[1])
                    print sql
                    print

        cursor.close()
        return self


    ####################################################################################################################
    def import_file (self, file_name):
        '''
        Load the entire object structure from disk.

        @see: export_file()

        @type  file_name:   String
        @param file_name:   File name to import from

        @rtype:             code_coverage
        @return:            self
        '''

        fh  = open(file_name, "rb")
        tmp = cPickle.loads(zlib.decompress(fh.read()))
        fh.close()

        self.hits        = tmp.hits
        self.num         = tmp.num
        self.heavy       = tmp.heavy
        self.mysql       = tmp.mysql
        self.main_module = tmp.main_module

        return self


    ####################################################################################################################
    def import_mysql (self, target_id, tag_id):
        '''
        Import code coverage from MySQL. Expects connection to database to already exist via self.mysql.

        @see: clear_mysql(), connect_mysql(), export_mysql()

        @type  target_id: Integer
        @param target_id: Name of target currently monitoring code coverage of
        @type  tag_id:    Integer
        @param tag_id:    Name of this code coverage run

        @rtype:  code_coverage
        @return: self
        '''

        self.reset()

        hits = self.mysql.cursor(MySQLdb.cursors.DictCursor)
        hits.execute("SELECT * FROM cc_hits WHERE target_id='%d' AND tag_id='%d'" % (target_id, tag_id))

        for hit in hits.fetchall():
            ccs = __code_coverage_struct__()

            ccs.eip         = hit["eip"]
            ccs.tid         = hit["tid"]
            ccs.num         = hit["num"]
            ccs.timestamp   = hit["timestamp"]
            ccs.module      = hit["module"]
            ccs.base        = hit["base"]
            ccs.is_function = hit["is_function"]

            if self.heavy:
                ccs.eax    = hit["eax"]
                ccs.ebx    = hit["ebx"]
                ccs.ecx    = hit["ecx"]
                ccs.edx    = hit["edx"]
                ccs.edi    = hit["edi"]
                ccs.esi    = hit["esi"]
                ccs.ebp    = hit["ebp"]
                ccs.esp    = hit["esp"]
                ccs.esp_4  = hit["esp_4"]
                ccs.esp_8  = hit["esp_8"]
                ccs.esp_C  = hit["esp_c"]
                ccs.esp_10 = hit["esp_10"]

                ccs.eax_deref    = hit["eax_deref"]
                ccs.ebx_deref    = hit["ebx_deref"]
                ccs.ecx_deref    = hit["ecx_deref"]
                ccs.edx_deref    = hit["edx_deref"]
                ccs.edi_deref    = hit["edi_deref"]
                ccs.esi_deref    = hit["esi_deref"]
                ccs.ebp_deref    = hit["ebp_deref"]
                ccs.esp_deref    = hit["esp_deref"]
                ccs.esp_4_deref  = hit["esp_4_deref"]
                ccs.esp_8_deref  = hit["esp_8_deref"]
                ccs.esp_C_deref  = hit["esp_c_deref"]
                ccs.esp_10_deref = hit["esp_10_deref"]

            if not self.hits.has_key(ccs.eip):
                self.hits[ccs.eip] = []

            self.hits[ccs.eip].append(ccs)
            self.num += 1

        hits.close()
        return self


    ####################################################################################################################
    def reset (self):
        '''
        Reset the internal counter and hit list dictionary.

        @rtype:  code_coverage
        @return: self
        '''

        self.hits = {}
        self.num  = 1
