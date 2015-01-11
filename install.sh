#!/bin/sh
#

echo "Installing recotak client"
cd recotak
./install.py --all --no-confirm
cd ..

echo "Installing recotak daemon"
cd recotakd
./install.py --all --no-confirm
cd ..

echo "Done"
