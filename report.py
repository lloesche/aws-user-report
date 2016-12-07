#!/usr/bin/env python3
import boto3
import time
import parsedatetime
import datetime
import csv
import sys
import io
import argparse
import logging
from multiprocessing.pool import ThreadPool
from pprint import pprint
import threading

logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(logging.DEBUG)
logging.getLogger('UserReport').setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


def main(argv):
    p = argparse.ArgumentParser(description='Generate AWS IAM User Report')
    p.add_argument('--access-key-id', help='AWS Access Key ID',
                   dest='access_key_id')
    p.add_argument('--secret-access-key', help='AWS Secret Access Key',
                   dest='secret_access_key')
    args = p.parse_args(argv)

    ur = UserReport(args)
    pprint(ur.report())


class UserReport:
    def __init__(self, args):
        self.args = args
        self._cal = parsedatetime.Calendar()
        self.log = logging.getLogger(__name__)

    def report(self):
        self.log.info('Generating Report')
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        iam = session.client('iam')
        complete = False
        while not complete:
            resp = iam.generate_credential_report()
            complete = resp['State'] == 'COMPLETE'
            time.sleep(1)

        report = iam.get_credential_report()

        if report['ReportFormat'] != 'text/csv':
            raise RuntimeError('Unknown Format {}'.format(report['ReportFormat']))

        # report_date = report['GeneratedTime']
        report_csv = io.StringIO(report['Content'].decode('utf-8'))
        reader = csv.DictReader(report_csv)

        users = list(reader)
        p = ThreadPool(50)
        return list(p.map(self.add_user_properties, users))

    def add_user_properties(self, user):
        self.log.debug('Assembling Properties for user {}'.format(user['user']))
        user['groups'] = self.user_groups(user['user'])
        user['policies'] = self.user_policies(user['user'])
        return user

    def user_groups(self, user):
        if user == '<root_account>':
            return ['root']
        self.log.debug('Fetching Groups for user {}'.format(user))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        iam = session.client('iam')
        complete = False
        marker = None
        ui = []
        while not complete:
            if marker:
                items = iam.list_groups_for_user(UserName=user, Marker=marker)
            else:
                items = iam.list_groups_for_user(UserName=user)
            if items['IsTruncated']:
                marker = items['Marker']
            else:
                complete = True

            for group in items['Groups']:
                ui.append(group['GroupName'])
        return ui

    def user_policies(self, user):
        if user == '<root_account>':
            return []
        self.log.debug('Fetching Policies for user {}'.format(user))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        iam = session.client('iam')
        complete = False
        marker = None
        ui = []
        while not complete:
            if marker:
                items = iam.list_user_policies(UserName=user, Marker=marker)
            else:
                items = iam.list_user_policies(UserName=user)
            if items['IsTruncated']:
                marker = items['Marker']
            else:
                complete = True

            ui.extend(items['PolicyNames'])
        return ui


if __name__ == "__main__":
    main(sys.argv[1:])