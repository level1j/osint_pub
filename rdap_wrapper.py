#!/usr/bin/python3
import tldextract
import defang
import argparse
import datetime
import dateutil.parser
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

def get_validate_domain(domain):
    class bcolors:
        WARNING = '\033[93m'
        ENDC = '\033[0m'
    ext = tldextract.extract(domain)
    if ext.registered_domain != domain:
        print(bcolors.WARNING + '{} is not domain. {} is modified to {}'.format(domain, domain, ext.registered_domain) + bcolors.ENDC, file=sys.stderr)
    return ext.registered_domain

def remove_tel(string):
    s = re.search('tel:(?P<tel>[0-9-]+)', string, re.IGNORECASE)
    if s:
        return s.group('tel')
    return string

def execute_rdap_save(domain):
    filename = domain + '_rdap_' + get_now() + '.txt'
    filepath = pathlib.Path(filename)
    with filepath.open(mode='w') as f:
        subprocess.run(['rdap', '-j', domain], stdout=f, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    return filename

def get_domain_items_from_file(rdap_json_file):
    filepath = pathlib.Path(rdap_json_file)
    with filepath.open(mode='r') as f:
        try:
            content_dict = json.load(f)
            domain_items = get_domain_items(content_dict)
        except json.decoder.JSONDecodeError:
            domain_items = {}
    return domain_items

def get_domain_items(content_dict):
    domain_items = {}
    domain_items['domain'] = get_domain_item_domain(content_dict)
    domain_items['registration'] = get_domain_item_registration(content_dict)
    domain_items['expiration'] = get_domain_item_expiration(content_dict)
    domain_items['nameservers'] = get_domain_item_nameservers(content_dict)
    domain_items['registrar'] = get_domain_item_registrar(content_dict)
    domain_items['registrant'] = get_domain_item_registrant(content_dict)
    domain_items['vcards'] = get_domain_items_entities(content_dict)
    return domain_items

def get_domain_item_domain(content_dict):
    return content_dict['ldhName'].lower()

def get_domain_item_registration(content_dict):
    for event in content_dict['events']:
        if event['eventAction'].upper() == 'registration'.upper():
            return get_standard_date_format(event['eventDate'])
    return None

def get_domain_item_expiration(content_dict):
    for event in content_dict['events']:
        if event['eventAction'].upper() == 'expiration'.upper():
            return get_standard_date_format(event['eventDate'])
    return None

def get_domain_item_nameservers(content_dict):
    nameservers = []
    for nameserver in content_dict['nameservers']:
        if nameserver['objectClassName'].upper() == 'nameserver'.upper():
            nameservers.append(nameserver['ldhName'])
    return nameservers

def get_domain_items_entities(content_dict):
    vcards = {}
    if 'entities' in content_dict:
        for entity in content_dict['entities']:
            roles = ','.join(entity['roles'])
            vcards[roles] = {}
            for e in entity['vcardArray'][1][1:]:
                if e[3] == '':
                    continue
                if e[0] == 'tel':
                    e[3] = remove_tel(e[3])
                vcards[roles][e[0]] = e[3]
            if len(vcards[roles]) == 0:
                del vcards[roles]
            vcards_recursive = get_domain_items_entities(entity)
            vcards.update(vcards_recursive)
    return vcards

def get_domain_item_registrar(content_dict):
    vcards = get_domain_items_entities(content_dict)
    return vcards['registrar']['fn']

def get_domain_item_registrant(content_dict):
    vcards = get_domain_items_entities(content_dict)
    return vcards.get('registrant', {})
    #for test
    #return vcards['abuse']

'''
def get_domain_item_registrar(content_dict):
    nameservers = []
    for entity in content_dict['entities']:
        if 'registrar' in entity['roles']:
            #https://tools.ietf.org/html/rfc7095
            #3.2.jCard Object and Syntactic Entities
            for e in entity['vcardArray'][1]:
                if e[0] == 'fn':
                    return e[3]
    return None
'''

def output(domain_items_list, output_tsv, output_json):
    if output_tsv:
        columns = ['domain', 'registrar', 'registration', 'expiration', 'nameservers', 'email', 'name', 'organization', 'phone', 'address']
        print('\t'.join(columns))
        output_string = ''
        for domain_items in domain_items_list:
            for column in columns:
                if column == 'nameservers':
                    column_string = ','.join(domain_items.get(column,[]))
                elif column == 'email' or column == 'name' or column == 'organization' or column == 'address':
                    if 'registrant' not in domain_items:
                        column_string = ''
                    else:
                        column_string = domain_items['registrant'].get(column, '')
                elif column == 'phone':
                    if 'registrant' not in domain_items:
                        column_string = ''
                    else:
                        column_string = domain_items['registrant'].get('tel', '')
                else:
                    column_string = domain_items.get(column)
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

def execute_rdap_save_list(domain_list):
    domaint_items_list = []
    for domain in domain_list:
        domain = get_validate_domain(domain)
        rdap_json_file = execute_rdap_save(domain)
        domain_items = get_domain_items_from_file(rdap_json_file)
        domaint_items_list.append(domain_items)
    return domaint_items_list

def parse_options():
    parser = argparse.ArgumentParser(description='rdap wrapper')
    parser.add_argument('-d', '--domain', dest='domains', help='domain1[,domain2]')
    parser.add_argument('-f', '--file', action='store', dest='domain_file', help='domain list file')
    parser.add_argument('-r', '--rdap', dest='rdap_json_file', help='rdap json file')
    parser.add_argument('-t', '--tsv', action='store_true', dest='output_tsv', default=False, help='output tsv')
    parser.add_argument('-j', '--json', action='store_true', dest='output_json', default=False, help='output json')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    if args.domains or args.domain_file:
        domain_list = parse_domain(args.domains, args.domain_file)
        domaint_items_list = execute_rdap_save_list(domain_list)
    if args.rdap_json_file:
        domain_items = get_domain_items_from_file(args.rdap_json_file)
        domaint_items_list = [domain_items]
    output(domaint_items_list, args.output_tsv, args.output_json)
