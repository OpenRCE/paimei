#
# PAIMEIdiff
# Copyright (C) 2006 Peter Silberman <peter.silberman@gmail.com>
#
# $Id: PAIMEIDiffReport.py 194 2007-04-05 15:31:53Z cameron $
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


import sys
import os
import wx
from time import *

BEGIN_HTML =   "<HTML>\n" \
               "<HEAD>\n" \
               "<TITLE>\n" \
               "PAIMEIDiff v1.0\n" \
               "</TITLE>\n" \
               "</HEAD>\n" \
               "<BODY>\n" 

END_HTML = "</BODY>\n" \
           "</HTML>\n"

HEADER = "<center><h1>PAIMEIDiff %s Report %s</h1></center>\n"

BEGIN_TABLE = "<table border=%d borderwidth=%d><tr><td>\n"

BEGIN_TABLE_WIDTH = "<table border=%d borderwidth=%d width=%d><tr><td>\n"

BEGIN_TABLE_WIDTH_ALIGN = "<table border=%d borderwidth=%d width=%d align=%s><tr><td>\n"

END_TABLE = "</td>\n" \
            "</tr>\n" \
            "</table>\n"

BEGIN_TR = "<tr>\n"

BEGIN_TD = "<td>\n"

END_TR = "</tr>\n"

END_TD = "</td>\n"

FONT_SIZE = "<font face=%s size=%d>\n"

FONT_COLOR = "<font color=%s>\n"
                    
BR = "<br>\n"

HR = "<hr>\n"

PAR = "<p>\n"

BEGIN_BOLD = "<b>\n"

END_BOLD = "</b>\n"

BEGIN_ITALIC = "<i>\n"

END_ITALIC = "</i>\n"

BEGIN_LINK = "<a href=\"%s\">\n"

A_NAME = "<a name=\"%s\">\n"

END_LINK = "</a>\n"

BEGIN_LIST = "<ul>\n"

END_LIST = "</ul>\n"

BEGIN_LI = "<li>\n"

END_LI = "</li>\n"



default_integer_color = "red"

default_font_color = "black"

default_address_color = "green"

default_disasm_color = "blue"

class PAIMEIDiffReport:
    def __init__(self, parent, path):
        self.parent = parent
        self.report_name = ""
        self.path = path

    ####################################################################################################################
    def generate_unmatched_b(self):
        name = self.path + self.parent.module_b_name + "_unmatched_b.html"
        out_file = open(name, "w")
        out_file.write(BEGIN_HTML)
        time_date = strftime("%a %b %d %H:%M:%S %Y",gmtime())
        out_file.write(HEADER % (self.parent.module_b_name,time_date) )
        #start main
        out_file.write(BEGIN_TABLE % (0,0) )
        
        #setup menu
        out_file.write(BEGIN_TABLE % (0,0) )
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + ".html") )
        out_file.write( "Matched" + END_LINK + BR)
        #write link to Un-Matched A
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + "_unmatched_a.html") )
        out_file.write( "Un-Matched A" + END_LINK + BR)
        #write link to Un-Matched B
        out_file.write( BEGIN_BOLD + "Un-Matched B" + END_BOLD + BR)
        #write link to Statistics
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + "_statistics.html" ))
        out_file.write( "Statistics" + END_LINK + BR)
        #end table
        out_file.write(END_TABLE)
        
        #write </td><td>
        out_file.write(END_TD + BEGIN_TD)
        
        #write module table
        out_file.write(BEGIN_TABLE_WIDTH % (0,0,600))
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write("Un-Matched Module B (%s) Functions" % self.parent.module_b_name) 
        out_file.write(END_TD + END_TR)
        #loop through all the matched function names
        for func_b in self.parent.UnMatchedBListCtrl.function_list:
            out_file.write(BEGIN_TR + BEGIN_TD)
            out_file.write(BEGIN_LINK % ("#" + func_b.name))
            out_file.write(FONT_SIZE % ("Tahoma",2) )
            out_file.write("%s" % func_b.name)
            out_file.write(END_LINK)
            out_file.write(END_TD + END_TR)
            
        out_file.write(END_TABLE)
        #end main table
        out_file.write(END_TABLE)
        i = 0
        while i < len( self.parent.UnMatchedBListCtrl.function_list):
            func_b =  self.parent.UnMatchedBListCtrl.function_list[i]
            out_file.write(BEGIN_TABLE_WIDTH_ALIGN % (0,0,600,"center") )
            out_file.writelines( self.generate_function_header(func_b))
            out_file.write( END_TD + END_TR)
            out_file.write(HR)
            a=0
            for bb in func_b.sorted_nodes():
                out_file.write(BEGIN_TR + BEGIN_TD)
                out_file.writelines( self.generate_bb_header(bb) )
                out_file.write(END_TD + END_TR + BEGIN_TR + BEGIN_TD)
                out_file.writelines( self.generate_instruction_text( bb) )
                out_file.write(END_TD + END_TR)
                a+=1
            i+=1
        out_file.write(END_TABLE)
        out_file.write(END_HTML)
        out_file.close()
    
    ####################################################################################################################
    def generate_unmatched_a(self):
        name = self.path + self.parent.module_a_name + "_unmatched_a.html"
        out_file = open(name, "w")
        out_file.write(BEGIN_HTML)
        time_date = strftime("%a %b %d %H:%M:%S %Y",gmtime())
        out_file.write(HEADER % (self.parent.module_a_name,time_date) )
        #start main
        out_file.write(BEGIN_TABLE % (0,0) )
        
        #setup menu
        out_file.write(BEGIN_TABLE % (0,0) )
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + ".html") )
        out_file.write( "Matched" + END_LINK + BR)
        #write link to Un-Matched A
        out_file.write( BEGIN_BOLD + "Un-Matched A" + END_BOLD + BR)
        #write link to Un-Matched B
        out_file.write( BEGIN_LINK % (self.parent.module_b_name + "_unmatched_b.html") )
        out_file.write( "Un-Matched B" + END_LINK + BR)
        #write link to Statistics
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + "_statistics.html" ))
        out_file.write( "Statistics" + END_LINK + BR)
        #end table
        out_file.write(END_TABLE)
        
        #write </td><td>
        out_file.write(END_TD + BEGIN_TD)
        
        #write module table
        out_file.write(BEGIN_TABLE_WIDTH % (0,0,600))
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write("Un-Matched Module A (%s) Functions" % self.parent.module_a_name) 
        out_file.write(END_TD + END_TR)
        #loop through all the matched function names
        for func_a in  self.parent.UnMatchedAListCtrl.function_list:
            out_file.write(BEGIN_TR + BEGIN_TD)
            out_file.write(BEGIN_LINK % ("#" + func_a.name))
            out_file.write(FONT_SIZE % ("Tahoma",2) )
            out_file.write("%s" % func_a.name)
            out_file.write(END_LINK)
            out_file.write(END_TD + END_TR)
            
        out_file.write(END_TABLE)
        #end main table
        out_file.write(END_TABLE)
        i = 0
        while i < len( self.parent.UnMatchedAListCtrl.function_list):
            func_a = self.parent.UnMatchedAListCtrl.function_list[i]
    
            out_file.write(BEGIN_TABLE_WIDTH_ALIGN % (0,0,600,"center") )
            out_file.writelines( self.generate_function_header(func_a))
            out_file.write( END_TD + END_TR)
            out_file.write(HR)
            a=0
            for bb in func_a.sorted_nodes():
                out_file.write(BEGIN_TR + BEGIN_TD)
                out_file.writelines( self.generate_bb_header(bb) )
                out_file.write(END_TD + END_TR + BEGIN_TR + BEGIN_TD)
                out_file.writelines( self.generate_instruction_text( bb) )
                out_file.write(END_TD + END_TR)
                a+=1
            i+=1
        out_file.write(END_TABLE)
        out_file.write(END_HTML)
        out_file.close()
    ####################################################################################################################
    def generate_report(self):
        self.report_name = self.path + "%s.html" % self.parent.module_a_name
        out_file = open(self.report_name, "w")
        out_file.write(BEGIN_HTML)
        time_date = strftime("%a %b %d %H:%M:%S %Y",gmtime())
        out_file.write(HEADER % (self.parent.module_a_name,time_date) )
        #start main
        out_file.write(BEGIN_TABLE % (0,0) )
        
        #setup menu
        out_file.write(BEGIN_TABLE % (0,0) )
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write( BEGIN_BOLD + "Matched" + END_BOLD + BR)
        #write link to Un-Matched A
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + "_unmatched_a.html") )
        out_file.write( "Un-Matched A" + END_LINK + BR)
        #write link to Un-Matched B
        out_file.write( BEGIN_LINK % (self.parent.module_b_name + "_unmatched_b.html") )
        out_file.write( "Un-Matched B" + END_LINK + BR)
        #write link to Statistics
        out_file.write( BEGIN_LINK % (self.parent.module_a_name + "_statistics.html" ))
        out_file.write( "Statistics" + END_LINK + BR)
        #end table
        out_file.write(END_TABLE)
        
        #write </td><td>
        out_file.write(END_TD + BEGIN_TD)
        
        #write module table
        out_file.write(BEGIN_TABLE_WIDTH % (0,0,600))
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write("Matched Module A (%s) Functions" % self.parent.module_a_name) 
        out_file.write(END_TD + BEGIN_TD)
        out_file.write(FONT_SIZE % ("Tahoma",2) )
        out_file.write("Matched Module B (%s) Functions" % self.parent.module_b_name)
        out_file.write(END_TD + END_TR)
        #loop through all the matched function names
        for (func_a,func_b) in self.parent.matched_list.matched_functions:
            out_file.write(BEGIN_TR + BEGIN_TD)
            out_file.write(BEGIN_LINK % ("#" + func_a.name))
            out_file.write(FONT_SIZE % ("Tahoma",2) )
            if func_a.ext["PAIMEIDiffFunction"].different:
                out_file.write("%s" % (func_a.name + "-DIFFERENT"))
            else:
                out_file.write("%s" % func_a.name)
            out_file.write(END_LINK)
            out_file.write(END_TD + BEGIN_TD)
            out_file.write(BEGIN_LINK % ("#" + func_a.name))
            out_file.write(FONT_SIZE % ("Tahoma",2) )
            if func_a.ext["PAIMEIDiffFunction"].different:
                out_file.write("%s" % (func_b.name + "-DIFFERENT"))
            else:
                out_file.write("%s" % func_b.name)
            out_file.write(END_LINK)
            out_file.write(END_TD + END_TR)
            
        out_file.write(END_TABLE)
        
        out_file.write(END_TD + END_TR + BEGIN_TR + BEGIN_TD)
        #end main table
        out_file.write(END_TABLE)
        i = 0
        a = 0
        b = 0
        bb_count = 0
        while i < len(self.parent.matched_list.matched_functions):
            out_file.write(BEGIN_TABLE_WIDTH_ALIGN % (0,0,600,"center"))
        
            func_a,func_b = self.parent.matched_list.matched_functions[i]
            out_file.write(BEGIN_TABLE_WIDTH_ALIGN % (0,0,600,"center") )
            out_file.writelines( self.generate_function_header(func_a) )    
            out_file.write(END_TD + END_TR)     
            for bb in func_a.sorted_nodes():
                out_file.write(BEGIN_TR + BEGIN_TD)
                out_file.writelines(self.generate_bb_header(bb))
                out_file.write(END_TD + END_TR + BEGIN_TR + BEGIN_TD)
                out_file.writelines(self.generate_instruction_text(bb))
                out_file.write(END_TD + END_TR)
            out_file.write(END_TABLE)
            
            out_file.write(END_TD + BEGIN_TD)
            
            out_file.write(BEGIN_TABLE_WIDTH_ALIGN % (0,0,600,"center") )
            out_file.writelines( self.generate_function_header(func_b) )    
            out_file.write(END_TD + END_TR) 
            for bb in func_b.sorted_nodes():
                out_file.write(BEGIN_TR + BEGIN_TD)
                out_file.writelines(self.generate_bb_header(bb))
                out_file.write(END_TD + END_TR + BEGIN_TR + BEGIN_TD)
                out_file.writelines(self.generate_instruction_text(bb))
                out_file.write(END_TD + END_TR)
            out_file.write(END_TABLE)
                       
            out_file.write(END_TABLE)
            i+=1
            
                
        out_file.write(END_HTML)
        out_file.close()
        self.generate_unmatched_a()
        self.generate_unmatched_b()
    
    ################################################################################################################
    def get_unmatched_bb(self, func):
        i = 0
        while i < len(func.nodes.values()):
            if not func.nodes.values()[i].ext["PAIMEIDiffBasicBlock"].touched:
                if not func.nodes.values()[i].ext["PAIMEIDiffBasicBlock"].matched or func.nodes.values()[i].ext["PAIMEIDiffBasicBlock"].ignore:
                    func.nodes.values()[i].ext["PAIMEIDiffBasicBlock"].touched = 1
                    return func.nodes.values()[i]
            i+=1
        return None
        
    ####################################################################################################################
    def generate_function_header(self, func):
        lines = []
        lines.append( FONT_SIZE % ("Tahoma",2))
        lines.append(A_NAME % func.name)
        lines.append(END_LINK)
        if not func.ext["PAIMEIDiffFunction"].different:
            lines.append( "<h2>" + BEGIN_BOLD + func.name + END_BOLD + "</h2>" + BR)
        else:
            lines.append( "<h2>" + BEGIN_BOLD + func.name + "-DIFFERENT"+ END_BOLD + "</h2>" + BR)
        lines.append(BEGIN_LIST)
        
        lines.append( BEGIN_LI + "BB Count: " + FONT_COLOR % default_integer_color)
        lines.append( "%d" % len(func.nodes.values()))
        lines.append(FONT_COLOR  % default_font_color)
        lines.append(END_LI)
        
        lines.append( BEGIN_LI + "Instruction Count: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % func.num_instructions)
        lines.append(FONT_COLOR % default_font_color)
        lines.append( END_LI)
        
        lines.append( BEGIN_LI + "Call Count: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % func.ext["PAIMEIDiffFunction"].num_calls)
        lines.append(FONT_COLOR % default_font_color)
        lines.append(END_LI)
        
        lines.append( BEGIN_LI + "Size: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % func.ext["PAIMEIDiffFunction"].size)
        lines.append(FONT_COLOR % default_font_color)
        lines.append(END_LI)
        
        lines.append(END_LIST)
        return lines
        
    ####################################################################################################################
    def generate_bb_header(self, bb):
        lines = []
        lines.append(FONT_SIZE % ("Tahoma",1) )
        lines.append(A_NAME % ( str(bb.ea_start) ) )
        lines.append(END_LINK)
        
        lines.append("Instruction Count: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % bb.num_instructions)
        lines.append(FONT_COLOR % default_font_color)
        lines.append(BR)
        
        lines.append("Call Count: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % bb.ext["PAIMEIDiffBasicBlock"].num_calls)
        lines.append(FONT_COLOR % default_font_color)
        lines.append(BR)
        
        lines.append("Size: " + FONT_COLOR % default_integer_color)
        lines.append("%d" % bb.ext["PAIMEIDiffBasicBlock"].size)
        lines.append(FONT_COLOR % default_font_color)
        lines.append(BR)

        return lines
        
    ####################################################################################################################
    def generate_instruction_text(self, bb):
        lines = []
        lines.append(FONT_SIZE % ("Tahoma",2) )
        for inst in bb.sorted_instructions():
            if bb.ext["PAIMEIDiffBasicBlock"].ignore or bb.num_instructions <= self.parent.insignificant_bb:
                lines.append(FONT_COLOR % "DarkGray")
                lines.append("0x%08x\n" % inst.ea)
                lines.append(FONT_COLOR % "DarkGray")
                lines.append("%s\n" %inst.disasm)
                lines.append(BR)
            elif not bb.ext["PAIMEIDiffBasicBlock"].matched:
                lines.append(FONT_COLOR % "red")
                lines.append("0x%08x\n" % inst.ea)
                lines.append(FONT_COLOR % "red")
                lines.append("%s\n" %inst.disasm)
                lines.append(BR)
            else:
                lines.append(FONT_COLOR % default_address_color)
                lines.append("0x%08x\n" % inst.ea)
                lines.append(FONT_COLOR % default_disasm_color)
                lines.append("%s\n" %inst.disasm)
                lines.append(BR)
            
        return lines
        