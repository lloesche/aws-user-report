# AWS IAM User Report
######Create HTML or JSON User Reports for one or more AWS Accounts
![AWS IAM User Report](https://raw.githubusercontent.com/lloesche/aws-user-report/master/misc/report.png "AWS IAM User Report")

## Introduction
Tool to create User reports for multiple AWS accounts with information
about who changed their password when and who's even using their accounts. 

## Usage Examples
Just dump a report with default credentials
```
./report.py > report.html
```
Dump a report in JSON format and use verbose logging
```
./report.py --verbose --json > report.json
```
Create Report for multiple AWS Accounts and send it by Email
```
./report.py --aws-credentials "Prod Account,AKIXXXXXXXX,XXXXXXXX" \
                              "Dev Account,AKIXXXXXXXX,XXXXXXXX" \
            --smtp-server smtp.mandrillapp.com \
            --smtp-port 587 \
            --smtp-login mysmtplogin \
            --smtp-password mysmtppassword \
            --smtp-from ops@example.com \
            --smtp-to lukas@example.com \
                      ops@example.com \
            --footer "&copy; 2016 ACME Inc."
```
