#!/usr/bin/python

import os
import sys
import email.parser
from email.header import decode_header
import dateutil.parser
import dkim
import csv
import re

header_row = ['id', 'has-sig', 'date', 'from', 'to', 'subject', 'message-id', 'verified']
unpleasant_chars = re.compile("[\n\r]")  # stuff that's not great in CSVs

def emit_csv(filename, email_directory):
    with open(filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='\"', quoting=csv.QUOTE_ALL)
        writer.writerow(header_row)
        process_emails(writer, email_directory)

def clean_header(h):
    return unpleasant_chars.sub(' ', ','.join([value for (value, encoding) in decode_header(h)]))

def process_emails(writer, email_directory):
    for filesplit in sorted(map(os.path.splitext, os.listdir(email_directory)),key = lambda f: int(f[0])):
        row = [int(filesplit[0])]
        filename = "".join(filesplit)
        f = open(filename, 'r')
        data = f.read()
        has_sig = False
        try:
            msg = email.message_from_string(data)
            date = dateutil.parser.parse(msg['date'])
            if msg['dkim-signature'] is not None:
                has_sig = True
            meta = [has_sig, date, clean_header(msg['from']), clean_header(msg['to']), clean_header(msg['subject']), clean_header(msg['message-id'])]
            row += meta
        except (RuntimeError, StandardError) as e:
            print "parse email exception %s" % e
            row += ['(could not parse)']
            pass

        try:
            verified = dkim.verify(data)
            if verified and has_sig:
                row.append("verified")
            elif has_sig:
                row.append("failed")
            else:
                row.append("unsigned")
        except (RuntimeError, StandardError, dkim.MessageFormatError) as e:
            print "DKIM verify exception on message %s: %s" % (filename, e)
            pass

        writer.writerow(row)

if __name__ == '__main__':
    emit_csv('../verify.csv', os.getcwd())
