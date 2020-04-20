#!/usr/bin/python3
import defang
import argparse
import datetime
import dateutil.parser
import subprocess
import tempfile
import pathlib
import os
import sys
import re
import json
import pprint

def get_now():
    d = datetime.datetime.now()
    return d.strftime('%Y%m%d%H%M')

def get_standard_date_format(string):
    d = dateutil.parser.parse(string)
    return d.strftime('%Y/%m/%d %H:%M:%S') + ' GMT'

def get_save_pem(servername):
    connect = servername + ':443'
    filename = servername + '_ssl_' + get_now() + '.txt'
    filepath = pathlib.Path(filename)
    with tempfile.NamedTemporaryFile(mode='w', dir=os.getcwd(), suffix=get_now(), delete=False) as tf:
        subprocess.run(['openssl', 's_client', '-connect', connect, '-servername', servername], stdout=tf, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    with filepath.open(mode='w') as f:
        subprocess.run(['openssl', 'x509', '-text', '-in', tf.name], stdout=f, stderr=subprocess.DEVNULL, shell=False)
    os.unlink(tf.name)
    return f.name

def get_certificate_items_from_file(cert_txt_file):
    p = subprocess.run(['openssl', 'x509', '-text', '-in', cert_txt_file], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    content = p.stdout.decode()
    if content == '':
        print('No certification file', file=sys.stderr)
        sys.exit()
    cert_items = get_certificate_items(content)
    return cert_items

def get_certificate_items(content):
    cert_items = {}
    cert_items['serial'] = get_certificate_items_serial(content)
    cert_items['issure'] = get_certificate_items_issure(content)
    cert_items['subject'] = get_certificate_items_subject(content)
    cert_items['cn'] = get_certificate_items_cn(cert_items['subject'])
    cert_items['sans'] = get_certificate_items_sans(content)
    cert_items['notbefore'] = get_certificate_items_notbefore(content)
    cert_items['notafter'] = get_certificate_items_notafter(content)
    return cert_items

def get_certificate_items_notbefore(content):
    s = re.search('\s*Not Before\s*:\s*(?P<notbefore>.+)', content, re.IGNORECASE)
    if s:
        return get_standard_date_format(s.group('notbefore'))
    else:
        return None

def get_certificate_items_notafter(content):
    s = re.search('\s*Not After\s*:\s*(?P<notafter>.+)', content, re.IGNORECASE)
    if s:
        return get_standard_date_format(s.group('notafter'))
    else:
        return None

def get_certificate_items_serial(content):
    s = re.search('Serial Number\s*:\s*\n*\s*(?P<serial>.+)', content, re.IGNORECASE)
    if s:
        return s.group('serial')
    else:
        return None

def get_certificate_items_issure(content):
    s = re.search('Issuer\s*:\s*(?P<issure>.+)', content, re.IGNORECASE)
    if s:
        return s.group('issure')
        #return get_x500attributetypes(s.group('issure'))
    else:
        return None

def get_certificate_items_subject(content):
    s = re.search('Subject\s*:\s*(?P<subject>.+)', content, re.IGNORECASE)
    if s:
        return s.group('subject')
        #return get_x500attributetypes(s.group('subject'))
    else:
        return None

def get_certificate_items_cn(subject):
    if subject is None:
        return None
    s = re.search('CN\s*=\s*(?P<cn>[^,]+)', subject, re.IGNORECASE)
    if s:
        return s.group('cn')
    else:
        return None

def get_certificate_items_sans(content):
    s = re.search('X509v3 Subject Alternative Name\s*:\s*\n\s*(?P<sans>.+)', content, re.IGNORECASE)
    if s:
        sans = s.group('sans')
        s = re.findall('DNS:(?P<dns>[^,]+)', sans, re.IGNORECASE)
        return s
    else:
        return None

'''
I could not parse the following well.
C=JP, O=Cybertrust Japan Co., Ltd., CN=Cybertrust Japan Public CA G3
def get_x500attributetypes(string):
    #https://www.ietf.org/rfc/rfc2253.txt
    X500ATTRIBUTETYPES = ['CN','L','ST','O','OU','C','STREET','DC','UID']
    attributes = {}
    for x in X500ATTRIBUTETYPES:
        pattern = x + '\s*=\s*(?P<x>[^,]+)'
        s = re.search(pattern, string, re.IGNORECASE)
        if s:
            attributes[x] = s.group('x')
    return attributes
'''

def output(cert_items, output_tsv, output_json):
    if output_tsv:
        columns = ['cn', 'subject', 'serial', 'issure', 'notbefore', 'notafter', 'sans']
        print('\t'.join(columns))
        output_string = ''
        for column in columns:
            if column == 'sans':
                cert_items[column] = ','.join(cert_items[column])
            output_string = output_string + cert_items[column] + '\t'
        output_string = output_string[:-1]
        print(output_string)
    elif output_json:
        output_string = json.dumps(cert_items)
        print(output_string)
    else:
        pprint.pprint(cert_items)
    return

def parse_options():
    parser = argparse.ArgumentParser(description='openssl wrapper')
    parser.add_argument('-s', '--servername', dest='servername', help='servername')
    parser.add_argument('-c', '--cert', dest='cert_file', help='cert file')
    parser.add_argument('-t', '--tsv', action='store_true', dest='output_tsv', default=False, help='output tsv')
    parser.add_argument('-j', '--json', action='store_true', dest='output_json', default=False, help='output json')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()

    if args.servername:
        servername = defang.refang(args.servername)
        cert_txt_file = get_save_pem(servername)
    if args.cert_file:
        cert_txt_file = args.cert_file
    cert_items = get_certificate_items_from_file(cert_txt_file)
    output(cert_items, args.output_tsv, args.output_json)
