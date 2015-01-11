#!/bin/bash
#01/11/2015
#
rclient="recotak"
rdaemon="recotakd"
cwd=`pwd`

echo "Installing recotak client"
cd $rclient
./install.py --all --no-confirm
cd $cwd

echo "Installing recotak daemon"
cd $rdaemon
./install.py --all --no-confirm
cd $cwd

#the runtime created password for the recotak superuser
echo "Username and password of the superuser:"
passw=`cat $rdaemon/recotak_credentials|grep Password|sed -s 's/Password: //g'`

echo "Want to make changes as superuser?"
echo "Login with:"
echo "recotak_client.py -a recotak:$passw 127.0.0.1:2401"

echo "Create a normal user for recotak usage"
echo "Username:"
read user
echo "Password:"
read upass

#create config
cp recotak/config/create.conf install.conf
sed -i 's/username=a/username='$user'/g' install.conf
sed -i 's/password=a/password='$upass'/g' install.conf

#add user
recotak_client.py -a recotak:$passw -c install.conf 127.0.0.1:2401

echo "Done"
