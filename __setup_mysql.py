#!c:\python\python.exe

# $Id: __setup_mysql.py 231 2008-07-21 22:43:36Z pedram.amini $

import MySQLdb
import sys

USAGE = "__setup_mysql.py <mysql host> <username> <password>"
error = lambda msg: sys.stderr.write("ERROR> " + msg + "\n") or sys.exit(1)

if len(sys.argv) != 4:
    error(USAGE)

host     = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

try:
    mysql = MySQLdb.connect(host=host, user=username, passwd=password)
except MySQLdb.OperationalError, err:
    error("Failed connecting to MySQL server: %s" % err[1])

cursor = mysql.cursor()

try:
    cursor.execute("CREATE DATABASE paimei")
    cursor.execute("USE paimei")

    cursor.execute("""CREATE TABLE cc_hits (
        target_id int(10) unsigned NOT NULL default '0',
        tag_id int(10) unsigned NOT NULL default '0',
        num int(10) unsigned NOT NULL default '0',
        timestamp int(10) unsigned NOT NULL default '0',
        eip int(10) unsigned NOT NULL default '0',
        tid int(10) unsigned NOT NULL default '0',
        eax int(10) unsigned NOT NULL default '0',
        ebx int(10) unsigned NOT NULL default '0',
        ecx int(10) unsigned NOT NULL default '0',
        edx int(10) unsigned NOT NULL default '0',
        edi int(10) unsigned NOT NULL default '0',
        esi int(10) unsigned NOT NULL default '0',
        ebp int(10) unsigned NOT NULL default '0',
        esp int(10) unsigned NOT NULL default '0',
        esp_4 int(10) unsigned NOT NULL default '0',
        esp_8 int(10) unsigned NOT NULL default '0',
        esp_c int(10) unsigned NOT NULL default '0',
        esp_10 int(10) unsigned NOT NULL default '0',
        eax_deref text NOT NULL,
        ebx_deref text NOT NULL,
        ecx_deref text NOT NULL,
        edx_deref text NOT NULL,
        edi_deref text NOT NULL,
        esi_deref text NOT NULL,
        ebp_deref text NOT NULL,
        esp_deref text NOT NULL,
        esp_4_deref text NOT NULL,
        esp_8_deref text NOT NULL,
        esp_c_deref text NOT NULL,
        esp_10_deref text NOT NULL,
        is_function int(1) unsigned NOT NULL default '0',
        module varchar(255) NOT NULL default '',
        base int(10) unsigned NOT NULL default '0',
        PRIMARY KEY  (target_id,tag_id,num),
        KEY tag_id (tag_id),
        KEY target_id (target_id)
        ) ENGINE=MyISAM""")

    cursor.execute("""CREATE TABLE cc_tags (
        id int(10) unsigned NOT NULL auto_increment,
        target_id int(10) unsigned NOT NULL default '0',
        tag varchar(255) NOT NULL default '',
        notes text NOT NULL,
        PRIMARY KEY  (id)
        ) ENGINE=MyISAM""")

    cursor.execute("""CREATE TABLE cc_targets (
        id int(10) unsigned NOT NULL auto_increment,
        target varchar(255) NOT NULL default '',
        notes text NOT NULL,
        PRIMARY KEY  (id)
        ) ENGINE=MyISAM""")

    cursor.execute("""CREATE TABLE pp_hits (
        id int(10) unsigned NOT NULL auto_increment,
        recon_id int(10) unsigned NOT NULL default '0',
        timestamp int(10) unsigned NOT NULL default '0',
        tid int(10) unsigned NOT NULL default '0',
        eax int(10) unsigned NOT NULL default '0',
        ebx int(10) unsigned NOT NULL default '0',
        ecx int(10) unsigned NOT NULL default '0',
        edx int(10) unsigned NOT NULL default '0',
        edi int(10) unsigned NOT NULL default '0',
        esi int(10) unsigned NOT NULL default '0',
        ebp int(10) unsigned NOT NULL default '0',
        esp int(10) unsigned NOT NULL default '0',
        esp_4 int(10) unsigned NOT NULL default '0',
        esp_8 int(10) unsigned NOT NULL default '0',
        esp_c int(10) unsigned NOT NULL default '0',
        esp_10 int(10) unsigned NOT NULL default '0',
        eax_deref text NOT NULL,
        ebx_deref text NOT NULL,
        ecx_deref text NOT NULL,
        edx_deref text NOT NULL,
        edi_deref text NOT NULL,
        esi_deref text NOT NULL,
        ebp_deref text NOT NULL,
        esp_deref text NOT NULL,
        esp_4_deref text NOT NULL,
        esp_8_deref text NOT NULL,
        esp_c_deref text NOT NULL,
        esp_10_deref text NOT NULL,
        base int(10) unsigned NOT NULL default '0',
        boron_tag varchar(255) NOT NULL default '',
        module_id int(10) unsigned NOT NULL default '0',
        PRIMARY KEY  (id)
        ) ENGINE=MyISAM""")

    cursor.execute("""CREATE TABLE pp_modules (
        id int(10) unsigned NOT NULL auto_increment,
        name varchar(255) NOT NULL default '',
        base int(10) unsigned NOT NULL default '0',
        notes text NOT NULL,
        PRIMARY KEY  (id)
        ) ENGINE=MyISAM""")

    cursor.execute("""CREATE TABLE pp_recon (
        id int(10) unsigned NOT NULL auto_increment,
        module_id int(10) unsigned NOT NULL default '0',
        offset int(10) unsigned NOT NULL default '0',
        stack_depth int(2) unsigned NOT NULL default '0',
        reason text NOT NULL,
        status varchar(255) NOT NULL default '',
        username varchar(255) NOT NULL default '',
        boron_tag varchar(255) NOT NULL default '',
        notes text NOT NULL,
        PRIMARY KEY  (id)
        ) ENGINE=MyISAM""")

except MySQLdb.ProgrammingError, err:
    error("Failed creating db / tables: %s" % err[1])

cursor.close()