#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: UnmatchedList.py 194 2007-04-05 15:31:53Z cameron $
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

class UnmatchedList:
    def __init__(self):
        self.unmatched_module_a = []
        self.unmatched_module_b = []

    ####################################################################################################################    
    def add_to_unmatched_a(self, func):
        self.unmatched_module_a.append(func)

    ####################################################################################################################
    def add_to_unmatched_b(self, func):
        self.unmatched_module_b.append(func)

    ####################################################################################################################
    def remove_unmatched_a(self, i):
        func = self.unmatched_module_a[ i ]
        del self.unmatched_module_a[ i ]
        return func

    ####################################################################################################################
    def remove_unmatched_b(self, i):
        func = self.unmatched_module_b[ i ]
        del self.unmatched_module_b[ i ]
        return func
        

            
