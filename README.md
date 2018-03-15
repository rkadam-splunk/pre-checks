How to setups,

You will get three files,

1) setup.sh
2) app_pre_checks.py
3) api.github.com.pem

step 1) run setup.sh ```~$ ./setup.sh``` <br />
step 2) in app_pre_checks.py, replace your username and password in jira_user and jira_password variable <br />
step 3) make sure api.github.com.pem file is in the same directory of app_pre_checks.py <br />

Now for each time run the script as per below,

```
~$ sudo python app_pre_checks.py -i 1234,5678,1234 -s stack
```

here 
-i: app ids  <br />
-s: stack name

This will generate pre-checks output (already formatted)

If you have any doubt or any problem occurs, discuss it to make it more mature.
