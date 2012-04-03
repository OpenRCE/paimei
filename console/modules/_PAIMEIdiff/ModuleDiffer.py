
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: ModuleDiffer.py 194 2007-04-05 15:31:53Z cameron $
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
@author:       Peter Silberman
@license:      GNU General Public License 2.0 or later
@contact:      peter.silberman@gmail.com
@organization: www.openrce.org
'''

import time
import wx

import pida

class ModuleDiffer:
    def __init__(self, parent):
        self.parent = parent
        
    ####################################################################################################################
    def diff_modules(self):
        i = 0
        idx = 0
        busy = wx.BusyInfo("Diffing basic blocks...stand by.")
        wx.Yield()
        start = time.time()
            
        while i < len(self.parent.used_diff_function_table):
#            print "Applying %s algorithm" % (sorted(self.parent.used_diff_function_table.keys())[i][1:])
            idx = 0
            while idx < len(self.parent.matched_list.matched_functions):
                (func_a,func_b) = self.parent.matched_list.matched_functions[idx]
                if func_a.ext["PAIMEIDiffFunction"].num_bb_id != len(func_a.sorted_nodes()) or func_b.ext["PAIMEIDiffFunction"].num_bb_id != len(func_b.sorted_nodes()):
                    if func_a.ext["PAIMEIDiffFunction"].spp != func_b.ext["PAIMEIDiffFunction"].spp and func_a.ext["PAIMEIDiffFunction"].smart_md5 != func_b.ext["PAIMEIDiffFunction"].smart_md5 and func_a.ext["PAIMEIDiffFunction"].neci != func_b.ext["PAIMEIDiffFunction"].neci:
                        if not func_a.ext["PAIMEIDiffFunction"].different and not func_b.ext["PAIMEIDiffFunction"].different and self.parent.used_diff_function_table[ sorted(self.parent.used_diff_function_table.keys())[i] ](func_a,func_b):
#                    if self.parent.used_diff_function_table[ sorted(self.parent.used_diff_function_table.keys())[i] ](func_a,func_b):
#                        print "Diff: %s %s marked as different due to %s" % (func_a.name, func_b.name, sorted(self.parent.used_diff_function_table.keys())[i][1:])
                            self.parent.matched_list.mark_function_as_different(idx)
#                        else:
#                            print "Passing due to not different on %s %s" % (func_a.name, func_b.name)
#                    else:
#                        print "Passing due to SSP or Smart MD5 on %s %s" % ( func_a.name, func_b.name)
#                else:
#                    print "Passing on %s (%d == %d) %s (%d == %d)" % (func_a.name,func_a.ext["PAIMEIDiffFunction"].num_bb_id,len(func_a.sorted_nodes()), func_b.name, func_b.ext["PAIMEIDiffFunction"].num_bb_id, len(func_b.sorted_nodes()))
                idx+=1
            i+=1
        self.parent.msg("Diffed module in %.2f seconds." % (round(time.time() - start, 3) ) ) 
