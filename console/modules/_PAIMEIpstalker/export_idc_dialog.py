#
# PaiMei
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: export_idc_dialog.py 194 2007-04-05 15:31:53Z cameron $
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
import wx
import wx.lib.colourselect as csel
import MySQLdb
import time

########################################################################################################################
class export_idc_dialog (wx.Dialog):
    '''
    Export the stalked informaton for the specified tag id into an IDC file.
    '''

    FUNCTIONS    = 0
    BASIC_BLOCKS = 1

    OVERRIDE     = 0
    IGNORE       = 1
    BLEND        = 2

    def __init__(self, *args, **kwds):
        self.parent    = kwds["parent"]
        self.top       = kwds["top"]
        self.tag_id    = kwds["tag_id"]
        self.target_id = kwds["target_id"]

        # we remove our added dictionary args as wxDialog will complain about them if we don't.
        del(kwds["top"])
        del(kwds["tag_id"])
        del(kwds["target_id"])

        # begin wxGlade: export_idc_dialog.__init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.misc_staticbox  = wx.StaticBox(self, -1, "Miscellaneous Options")
        self.select_color    = csel.ColourSelect(self, -1, "Select Color", (0, 0, 60))
        self.color_depth     = wx.RadioBox(self, -1, "Color Depth", choices=["Functions", "Basic Blocks"], majorDimension=1, style=wx.RA_SPECIFY_ROWS)
        self.existing_colors = wx.RadioBox(self, -1, "Existing Colors", choices=["Override", "Ignore", "Blend"], majorDimension=1, style=wx.RA_SPECIFY_ROWS)
        self.add_comments    = wx.CheckBox(self, -1, "Add context data as comments")
        self.add_marks       = wx.CheckBox(self, -1, "Mark positions")
        self.ida_logo        = wx.StaticBitmap(self, -1, wx.Bitmap(self.top.main_frame.cwd + "/images/ida.bmp", wx.BITMAP_TYPE_ANY))
        self.export_idc      = wx.Button(self, -1, "Export IDC")

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

        # event handlers.
        self.Bind(wx.EVT_BUTTON, self.on_export_idc, self.export_idc)


    ####################################################################################################################
    def __set_properties(self):
        # begin wxGlade: export_idc_dialog.__set_properties
        self.SetTitle("Export to IDC")
        self.color_depth.SetSelection(1)
        self.existing_colors.SetSelection(1)
        # end wxGlade


    ####################################################################################################################
    def __do_layout(self):
        # begin wxGlade: export_idc_dialog.__do_layout
        overall = wx.BoxSizer(wx.HORIZONTAL)
        right = wx.BoxSizer(wx.VERTICAL)
        left = wx.BoxSizer(wx.VERTICAL)
        misc = wx.StaticBoxSizer(self.misc_staticbox, wx.VERTICAL)
        left.Add(self.select_color, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        left.Add(self.color_depth, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        left.Add(self.existing_colors, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        misc.Add(self.add_comments, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        misc.Add(self.add_marks, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        left.Add(misc, 1, wx.EXPAND, 0)
        overall.Add(left, 1, wx.EXPAND, 0)
        right.Add(self.ida_logo, 0, wx.ADJUST_MINSIZE, 0)
        right.Add(self.export_idc, 1, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        overall.Add(right, 0, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(overall)
        overall.Fit(self)
        overall.SetSizeHints(self)
        self.Layout()
        # end wxGlade


    ####################################################################################################################
    def on_export_idc (self, event):
        '''
        '''

        # ensure a MySQL connection is available.
        mysql = self.top.main_frame.mysql

        if not mysql:
            self.top.err("No available connection to MySQL server.")
            return

        # prompt the user for the IDC filename.
        dlg = wx.FileDialog(                                            \
            self,                                                       \
            message     = "IDC Filename",                               \
            defaultDir  = os.getcwd(),                                  \
            defaultFile = "",                                           \
            wildcard    = "*.idc",                                      \
            style       = wx.SAVE | wx.OVERWRITE_PROMPT | wx.CHANGE_DIR \
        )

        if dlg.ShowModal() != wx.ID_OK:
            self.top.msg("Export cancelled by user")
            self.Destroy()
            return

        # attempt to open the file and write the IDC header.
        try:
            filename = dlg.GetPath()
            idc      = open(filename, "w+")

            idc.write(self.idc_header)
        except:
            self.top.msg("Unable to open requested file: %s" % filename)
            self.Destroy()
            return

        self.Destroy()
        busy = wx.BusyInfo("Generating IDC script ... stand by.")
        wx.Yield()

        # extract the various dialog options.
        # IDA reads colors in reverse, ie: instead of #RRGGBB it understands 0xBBGGRR.
        wxcolor = self.select_color.GetColour()
        color   = "0x%02x%02x%02x" % (wxcolor.Blue(), wxcolor.Green(), wxcolor.Red())

        existing_colors = self.existing_colors.GetSelection()
        color_depth     = self.color_depth.GetSelection()
        add_comments    = self.add_comments.GetValue()
        add_marks       = self.add_marks.GetValue()

        # step through the hits for this tag id.
        hits = mysql.cursor(MySQLdb.cursors.DictCursor)
        hits.execute("SELECT hits.*, tags.tag FROM cc_hits AS hits, cc_tags AS tags WHERE hits.tag_id = '%d' AND tags.id = '%d' ORDER BY module ASC" % (self.tag_id, self.tag_id))

        current_module = ""
        base_modified  = False

        for hit in hits.fetchall():
            # if function level color depth was specified and the current hit is not for a function, ignore it.
            if color_depth == self.FUNCTIONS and not hit["is_function"]:
                continue

            # ensure we are working in the right module.
            if hit["module"] != current_module:
                if current_module != "":
                    idc.write("}\n")

                current_module = hit["module"]
                idc.write("\n    if (tolower(this_module) == \"%s\")\n    {\n" % current_module.lower())
                base_modified = False

            # if the base address for any hit in this module is 0, then set base to 0.
            if not hit["base"] and not base_modified:
                idc.write("        // no base for this module.\n")
                idc.write("        base = 0;\n\n");
                base_modified = True

            if add_comments:
                comment  = "[#%d] %s\n" % (hit["num"], time.ctime(hit["timestamp"]))
                comment += "eax: %08x (%10d) -> %s\n" % (hit["eax"], hit["eax"], hit["eax_deref"])
                comment += "ebx: %08x (%10d) -> %s\n" % (hit["ebx"], hit["ebx"], hit["ebx_deref"])
                comment += "ecx: %08x (%10d) -> %s\n" % (hit["ecx"], hit["ecx"], hit["ecx_deref"])
                comment += "edx: %08x (%10d) -> %s\n" % (hit["edx"], hit["edx"], hit["edx_deref"])
                comment += "edi: %08x (%10d) -> %s\n" % (hit["edi"], hit["edi"], hit["edi_deref"])
                comment += "esi: %08x (%10d) -> %s\n" % (hit["esi"], hit["esi"], hit["esi_deref"])
                comment += "ebp: %08x (%10d) -> %s\n" % (hit["ebp"], hit["ebp"], hit["ebp_deref"])
                comment += "esp: %08x (%10d) -> %s\n" % (hit["esp"], hit["esp"], hit["esp_deref"])
                comment += "+04: %08x (%10d) -> %s\n" % (hit["esp_4"],  hit["esp_4"],  hit["esp_4_deref"])
                comment += "+08: %08x (%10d) -> %s\n" % (hit["esp_8"],  hit["esp_8"],  hit["esp_8_deref"])
                comment += "+0C: %08x (%10d) -> %s\n" % (hit["esp_c"],  hit["esp_c"],  hit["esp_c_deref"])
                comment += "+10: %08x (%10d) -> %s"   % (hit["esp_10"], hit["esp_10"], hit["esp_10_deref"])

                comment = comment.replace('"', '\\"')

                idx = 0
                for line in comment.split("\n"):
                    idc.write("        ExtLinA(base + 0x%08x, %d, \"%s\");\n" % (hit["eip"] - hit["base"], idx, line))
                    idx += 1

            prefix = ""

            if existing_colors != self.BLEND:
                idc.write("\n        color = %s;" % color)

            if existing_colors == self.IGNORE:
                idc.write("\n        if (GetColor(base + 0x%08x, CIC_ITEM) == DEFCOLOR)" % (hit["eip"] - hit["base"]))
                prefix = "    "
            elif existing_colors == self.BLEND:
                idc.write("\n        color = blend_color(GetColor(base + 0x%08x, CIC_ITEM), %s);" % (hit["eip"] - hit["base"], color))

            if color_depth == self.FUNCTIONS:
                idc.write("\n%s        SetColor(base + 0x%08x, CIC_FUNC, color);\n\n" % (prefix, hit["eip"] - hit["base"]))
            else:
                idc.write("\n%s        assign_block_color_to(base + 0x%08x, color);\n\n" % (prefix, hit["eip"] - hit["base"]))

            if add_marks:
                idc.write("        MarkPosition(base + 0x%08x, 1,1,1, next_mark, \"tag: %s hit #%05d\");\n" % (hit["eip"] - hit["base"], hit["tag"], hit["num"]))
                idc.write("        next_mark++;\n\n");

        idc.write("    }\n")
        idc.write("}\n")
        idc.close()


    ####################################################################################################################
    '''
    Stock header with support functions and declarations for IDC export.
    '''

    idc_header = """//
// AUTO-GENERATED BY PAIMEI
// http://www.openrce.org
//

#include <idc.idc>

// convenience wrapper around assign_color_to() that will automatically resolve the 'start' and 'end' arguments with
// the start and end address of the block containing ea.
static assign_block_color_to (ea, color)
{
    auto block_start, block_end;

    block_start = find_block_start(ea);
    block_end   = find_block_end(ea);

    if (block_start == BADADDR || block_end == BADADDR)
        return BADADDR;

    assign_color_to(block_start, block_end, color);
}

// the core color assignment routine.
static assign_color_to (start, end, color)
{
    auto ea;

    if (start != end)
    {
        for (ea = start; ea < end; ea = NextNotTail(ea))
            SetColor(ea, CIC_ITEM, color);
    }
    else
    {
        SetColor(start, CIC_ITEM, color);
    }
}

// returns address of start of block if found, BADADDR on error.
static find_block_start (current_ea)
{
    auto ea, prev_ea;
    auto xref_type;

    // walk up from current ea.
    for (ea = current_ea; ea != BADADDR; ea = PrevNotTail(ea))
    {
        prev_ea = PrevNotTail(ea);

        // if prev_ea is the start of the function, we've found the start of the block.
        if (GetFunctionAttr(ea, FUNCATTR_START) == prev_ea)
            return prev_ea;

        // if there is a code reference *from* prev_ea or *to* ea.
        if (Rfirst0(prev_ea) != BADADDR || RfirstB0(ea) != BADADDR)
        {
            xref_type = XrefType();

            // block start found if the code reference was a JMP near or JMP far.
            if (xref_type == fl_JN || xref_type == fl_JF)
                return ea;
        }
    }

    return BADADDR;
}

// returns address of end of block if found, BADADDR on error.
static find_block_end (current_ea)
{
    auto ea, next_ea;
    auto xref_type;

    // walk down from current ea.
    for (ea = current_ea; ea != BADADDR; ea = NextNotTail(ea))
    {
        next_ea = NextNotTail(ea);

        // if next_ea is the start of the function, we've found the end of the block.
        if (GetFunctionAttr(ea, FUNCATTR_END) == next_ea)
            return next_ea;

        // if there is a code reference *from* ea or *to* next_ea.
        if (Rfirst0(ea) != BADADDR || RfirstB0(next_ea) != BADADDR)
        {
            xref_type = XrefType();

            // block end found if the code reference was a JMP near or JMP far.
            if (xref_type == fl_JN || xref_type == fl_JF)
                return next_ea;
        }
    }

    return BADADDR;
}

// return the lower case version of 'str'.
static tolower (str)
{
    auto i, c, new;

    new = "";

    for (i = 0; i < strlen(str); i++)
    {
        c = substr(str, i, i + 1);

        if (ord(c) >= 0x41 && ord(c) <= 0x5a)
            c = form("%s", ord(c) + 32);

        new = new + c;
    }

    return new;
}

// return the blended color between 'old' and 'new'.
static blend_color (old, new)
{
    auto r, g, b, bold, gold, rold, bnew, gnew, rnew;

    bold = (old & 0xFF0000) >> 16;
    gold = (old & 0x00FF00) >> 8;
    rold = (old & 0x0000FF);

    bnew = (new & 0xFF0000) >> 16;
    gnew = (new & 0x00FF00) >> 8;
    rnew = (new & 0x0000FF);

    b    = (bold + (bnew - bold) / 2) & 0xFF;
    g    = (gold + (gnew - gold) / 2) & 0xFF;
    r    = (rold + (rnew - rold) / 2) & 0xFF;

    return (b << 16) + (g << 8) + r;
}

// return the next empty Mark slot
static get_marked_next()
{
    auto slot;
    slot = 1;

    // loop until we find an empty slot
    while(GetMarkedPos(slot) != -1)
        slot++;

    return slot;
}

// executed on script load.
static main()
{
    auto base, color, this_module, next_mark;

    base        = MinEA() - 0x1000;    // cheap hack
    this_module = GetInputFile();
    next_mark = get_marked_next();
"""
