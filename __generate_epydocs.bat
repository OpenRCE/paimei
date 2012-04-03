REM $Id: __generate_epydocs.bat 231 2008-07-21 22:43:36Z pedram.amini $

set PythonPath=C:\Python25

%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\PyDbg     --css blue --name "PyDbg - Python Win32 Debugger" --url "http://www.openrce.org" pydbg\defines.py pydbg\breakpoint.py pydbg\hardware_breakpoint.py pydbg\memory_breakpoint.py pydbg\memory_snapshot_block.py pydbg\memory_snapshot_context.py pydbg\my_ctypes.py pydbg\pdx.py pydbg\pydbg.py pydbg\pydbg_core.py pydbg\system_dll.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\PIDA      --css blue --name "PIDA - Pedram's IDA"           --url "http://www.openrce.org" pida\defines.py pida\basic_block.py pida\function.py pida\instruction.py pida\module.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\pGRAPH    --css blue --name "pGRAPH - Pedram's Graphing"    --url "http://www.openrce.org" pgraph\cluster.py pgraph\edge.py pgraph\graph.py pgraph\node.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\Utilities --css blue --name "Utilities"                     --url "http://www.openrce.org" utils\code_coverage.py utils\crash_binning.py utils\process_stalker.py utils\udraw_connector.py utils\hooking.py
