#!/bin/sh

rm -f ollydbg_connector/paimei_ollydbg_connector.ncb

rm -rf deprecated
rm -rf docs/PAIMEIpstalker_flash_demo

find ./ -name .svn -exec rm -rf {} \;

./__build_installer.bat
./__generate_epydocs.bat

mv dist/PaiMei-1.2.win32.exe installers

rm -rf build
rm -rf dist

find ./ -name \*.pyc -exec rm -f {} \;