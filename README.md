# App install Prechecks - Automation

## Introduction

Most of the Maintenance Windows we get are mostly of App installations. One of the process is performing prechecks. It takes a lot of time of the SRE for app installations. This is the automation of the process so that a lot of the time of the SRE can be saved.

## Setup

The setup of the automation involves 4 files:

1. `setup.sh`, the script for installation of the dependencies required for the script to work.
2. `app_pre_checks.py` the main script for the automation, which performs all the pre-checks.
3. `variables.py` the script for providing the variables required for the automation. The SRE will provide the required credentials here.

The steps for getting started with the automation is as follows:

1. Run `setup.sh` for the first time for installing the dependencies.
2. Provide your credentials (`AD_USER`,`AD_PASSWORD`,`GITHUB_PERSONAL_ACCESS_TOKEN`,`ANSIBLE_VAULT`) in the `variables.py` file.
3. Run the `app_pre_checks.py` as follows:

    ```
        $ sudo python app_pre_checks.py -i <SPLUNKBASE_APP_IDS> -s <STACK_ID>
        Ex:
            $ sudo python app_pre_checks.py -i 1234,2345,3456 -s dt
    ```
    This will generate the output of the prechecks **pre-formatted** so that it can be pasted directly in the JIRA

Problems/Suggestions? Feel free to open an issue/PR!
