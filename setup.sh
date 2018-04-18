#!/bin/bash

pip -V
retval=$?
do_something $retval
if [ $retval -ne 0 ]; then
    echo "Something is wrong : $retval"
    echo "\n --- Looks like pip isn't installed on your machine... Installing pip --- \n"
    sudo easy_install pip
else
    sudo pip install jira confluence-py dnspython beautifulsoup4 beautifulsoup --ignore-installed six
    sudo pip install -U --user PyOpenSSL
    echo "\n --- Good to Go! --- \n"
fi