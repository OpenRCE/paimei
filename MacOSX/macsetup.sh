#!/bin/bash

cd ..

# Check for the modules we like to use
echo -n "Checking for module ctypes..."
python -m "ctypes" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "not found"
	sudo easy_install ctypes
else
	echo "found"
fi

echo -n "Checking for module pydot..."
python -m "pydot" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "not found"
	sudo easy_install pydot
else
	echo "found"
fi

echo -n "Checking for module wx..."
python -m "wx" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "not found"
	sudo easy_install wx
else
	echo "found"
fi

echo -n "Checking for module MySQLdb..."
python -m "MySQLdb" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "not found"
	sudo easy_install pydot
else
	echo "found"
fi

# Build install libmacdll
cd MacOSX/macdll
xcodebuild -target macdll -configuration release
cp -f build/Release/libmacdll.dylib ../../pydbg
cp -f build/Release/libmacdll.dylib ../../utils

