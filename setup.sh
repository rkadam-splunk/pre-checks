#!/bin/bash

pip -V
retval=$?
if [ $retval -ne 0 ]; then
    echo "Something is wrong : $retval"
    echo "--- Looks like pip isn't installed on your machine... Installing pip ---"
    sudo easy_install pip
else
    echo "--- pip is installed already. Great! ---"
    sudo pip install jira confluence-py dnspython beautifulsoup4 beautifulsoup --ignore-installed six
    sudo pip install -U --user PyOpenSSL
    echo "--- Good to Go! ---"
fi
