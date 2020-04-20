#!/usr/bin/python3
import whois
import tldextract
import defang
import datetime
import dateutil.parser
import argparse
import pathlib
import subprocess
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

def get_standard_date_format_d_list(d_list):
    new_d_list = []
    if d_list is None:
        return None
    elif isinstance(d_list, list):
        for d in d_list:
            new_d_list.append(d.strftime('%Y/%m/%d %H:%M:%S') + ' GMT')
    else:
        new_d_list.append(d_list.strftime('%Y/%m/%d %H:%M:%S') + ' GMT')
    return new_d_list

def get_validate_domain(domain):
    class bcolors:
        WARNING = '\033[93m'
        ENDC = '\033[0m'
    ext = tldextract.extract(domain)
    if ext.registered_domain != domain:
        print(bcolors.WARNING + '{} is not domain. {} is modified to {}'.format(domain, domain, ext.registered_domain) + bcolors.ENDC, file=sys.stderr)
    return ext.registered_domain

def execute_save_whois_domain_list(domain_list):
    domain_items_list = []
    for domain in domain_list:
        domain = get_validate_domain(domain)
        execute_save_whois(domain)
        domain_items = execute_python_whois(domain)
        domain_items_list.append(domain_items)
    return domain_items_list

def execute_save_whois(domain):
    filename = domain + '_whois_' + get_now() + '.txt'
    filepath = pathlib.Path(filename)
    with filepath.open(mode='w') as f:
        subprocess.run(['whois', domain], stdout=f, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    return filename

def execute_python_whois(domain):
    python_whois_result = whois.whois(domain)
    python_whois_result = unique_python_whois_result(python_whois_result)
    domain_items = get_domain_items(python_whois_result)
    domain_items['domain'] = domain
    return domain_items

def unique_python_whois_result(result):
    new_result = {}
    for k,v in result.items():
        if isinstance(v, list):
            if type(v[0]) is str:
                v = list(set([s.lower() for s in v]))
                v.sort()
        new_result[k] = v
    return new_result

def get_domain_items(python_whois_result):
    domain_items = {}
    domain_items['registrar'] = python_whois_result.get('registrar')
    domain_items['registration'] = get_standard_date_format_d_list(python_whois_result.get('creation_date'))
    domain_items['expiration'] = get_standard_date_format_d_list(python_whois_result.get('expiration_date'))
    domain_items['nameservers'] = python_whois_result.get('name_servers')
    domain_items['registrant'] = {}
    domain_items['registrant']['name'] = python_whois_result.get('name')
    domain_items['registrant']['organization'] = python_whois_result.get('org', python_whois_result.get('registrant_org'))
    domain_items['email'] = python_whois_result.get('emails')
    domain_items['registrant']['street'] = python_whois_result.get('address')
    domain_items['registrant']['city'] = python_whois_result.get('city')
    domain_items['registrant']['state'] = python_whois_result.get('state')
    domain_items['registrant']['postal'] = python_whois_result.get('zipcode')
    domain_items['registrant']['country'] = python_whois_result.get('country')
    return domain_items

def output(domain_items_list, output_tsv, output_json):
    if output_tsv:
        columns = ['domain', 'registrar', 'registration', 'expiration', 'nameservers', 'email', 'name', 'organization', 'phone', 'address']
        print('\t'.join(columns))
        for domain_items in domain_items_list:
            output_string = ''
            for column in columns:
                if column == 'domain' or column == 'registrar':
                    column_string = domain_items[column]
                elif column == 'registration' or column == 'expiration' or column == 'nameservers' or column == 'email':
                    if isinstance(domain_items[column], list):
                        column_string = ','.join(domain_items[column])
                    else:
                        column_string = domain_items[column]
                elif column == 'name' or column == 'organization':
                    column_string = domain_items['registrant'][column]
                elif column == 'phone':
                    column_string = None
                elif column == 'address':
                    flag_address_exist = False
                    column_string = ''
                    for a in ['street', 'city', 'state', 'postal', 'country']:
                        if domain_items['registrant'][a] is None:
                            column_string_registrant = ''
                        else:
                            if isinstance(domain_items['registrant'][a], list):
                                column_string_registrant = ','.join(domain_items['registrant'][a])
                            else:
                                column_string_registrant = domain_items['registrant'][a]
                            flag_address_exist = True
                        column_string = column_string + a + ':' + column_string_registrant + ','
                    if flag_address_exist:
                        column_string = column_string[:-1]
                    else:
                        column_string = None
                if column_string is None or column_string == '':
                    column_string = '-'
                output_string = output_string + column_string + '\t'
            output_string = output_string[:-1]
            print(output_string)
    elif output_json:
        output_string = json.dumps(domain_items_list)
        print(output_string)
    else:
        pprint.pprint(domain_items_list)
    return

def import_domain_file(domain_file):
    filepath = pathlib.Path(domain_file)
    with filepath.open(mode='r') as f:
        domain_list = []
        for domain in f:
            domain = domain.strip()
            if domain is not '' and domain not in domain_list:
                domain_list.append(domain)
    return domain_list

def parse_domain(domains, domain_file):
    domain_list = []
    if domains:
        domain_list.extend(domains.split(','))
    if domain_file:
        domain_list.extend(import_domain_file(domain_file))
    domain_list = list(set(domain_list))
    domain_list = list(map(lambda x: defang.refang(x), domain_list))
    return domain_list

def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', action='store', dest='domains', help='domain1[,domain2]')
    parser.add_argument('-f', '--file', action='store', dest='domain_file', help='domain list file')
    parser.add_argument('-t', '--tsv', action='store_true', dest='output_tsv', default=False, help='output tsv')
    parser.add_argument('-j', '--json', action='store_true', dest='output_json', default=False, help='output json')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    domain_list = parse_domain(args.domains, args.domain_file)
    domain_items_list = execute_save_whois_domain_list(domain_list)
    output(domain_items_list, args.output_tsv, args.output_json)
