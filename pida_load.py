#
# IDA Python PIDA Database Loading Script
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: pida_load.py 194 2007-04-05 15:31:53Z cameron $
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

import time
import pida

pida_name = AskFile(0, GetInputFile() + ".pida", "Load PIDA file from?")

if not pida_name:
    Warning("Cancelled.")
else:
    start = time.time()
    print "Loading %s" % pida_name
    module = pida.load(pida_name, progress_bar="ascii")
    print "Done. Completed in %f seconds." % round(time.time() - start, 3)
