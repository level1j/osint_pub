#!/usr/bin/python3
import defang
import tldextract
import dns.resolver
from urllib.parse import urlparse
import argparse
import pprint
import re
import datetime
import dateutil.parser
import pathlib
import json
import subprocess
import os
import sys

IP2AS_CYMRU = 'ip2as_cymru.py'
RDAP_AUTO = 'rdap_wrapper.py'
WHOIS_DOMAIN = 'whois_domain.py'
SSL_AUTO = 'ssl_wrapper.py'
SCREENSHOT = 'screenshot.py'

def get_now():
    d = datetime.datetime.now()
    return d.strftime('%Y%m%d%H%M')

def get_validate_url(url):
    class bcolors:
        WARNING = '\033[93m'
        ENDC = '\033[0m'
    url = defang.refang(url)
    o = urlparse(url)
    if o.scheme == '':
        newurl = 'https://' + url
        print(bcolors.WARNING + '{} doesn\'t have a scheme which is modified to {}'.format(url, newurl) + bcolors.ENDC, file=sys.stderr)
        url = newurl
    return url

def get_domain_from_dns(d):
    ext = tldextract.extract(d)
    return ext.registered_domain

def get_ip_from_dns(d):
    try:
        answers = dns.resolver.query(d, 'A')
        return str(answers[0])
    except dns.resolver.NXDOMAIN:
        return None

def parse_url(url):
    url = get_validate_url(url)
    o = urlparse(url)
    scheme = o.scheme
    hostname = o.hostname
    path = o.path
    domain = get_domain_from_dns(hostname)
    ip = get_ip_from_dns(hostname)
    return url, scheme, hostname, domain, path, ip

def execute_commands(url_list, flag_no_nmap):
    global IP2AS_CYMRU
    global RDAP_AUTO
    global WHOIS_DOMAIN
    global SSL_AUTO
    global SCREENSHOT

    print('url\tscheme\thostname\tdomain\tip')
    for url in url_list:
        url, scheme, hostname, domain, path, ip = parse_url(url)
        print('{}\t{}\t{}\t{}\t{}\t{}'.format(url, scheme, hostname, domain, path, ip))
        if ip is not None:
            print()
            subprocess.run(['python3', IP2AS_CYMRU, '-t', '-i', ip], stdin=subprocess.DEVNULL, shell=False)
            if scheme == 'https':
                print()
                subprocess.run(['python3', SSL_AUTO, '-t', '-s', hostname], stdin=subprocess.DEVNULL, shell=False)
        print()
        subprocess.run(['python3', RDAP_AUTO, '-t', '-d', domain], stdin=subprocess.DEVNULL, shell=False)
        print()
        subprocess.run(['python3', WHOIS_DOMAIN, '-t', '-d', domain], stdin=subprocess.DEVNULL, shell=False)
        if ip is not None:
            subprocess.run(['python3', SCREENSHOT, '-p', '-s', '--http-https', '--save-html', url], stdin=subprocess.DEVNULL, shell=False)
            print()
            if not flag_no_nmap:
                nmap_save_file(ip)

def nmap_save_file(ip):
    filename = ip + '_nmap_' + get_now() + '.txt'
    subprocess.run(['nmap', '-Pn', '-sV', '-sC', '-T4', '-oN', filename, ip], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, shell=False)
    return filename

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
    return domain_list

def parse_options():
    parser = argparse.ArgumentParser(description='Execute ip2as,whois_domain,rdap_wrapper,ssl_wrapper,screenshot')
    parser.add_argument('-u', '--url', dest='urls', help='url1[,url2]')
    parser.add_argument('-f', '--file', action='store', dest='url_file', help='url list file')
    parser.add_argument('--no-nmap', action='store_true', dest='flag_no_nmap', default=False, help='disable nmap')
    args = parser.parse_args()
    return args

def change_program_path():
    global IP2AS_CYMRU
    global RDAP_AUTO
    global WHOIS_DOMAIN
    global SSL_AUTO
    global SCREENSHOT
    program_dir = os.path.dirname(os.path.abspath(__file__))
    IP2AS_CYMRU = program_dir + '/' + IP2AS_CYMRU
    RDAP_AUTO = program_dir + '/' + RDAP_AUTO
    WHOIS_DOMAIN = program_dir + '/' + WHOIS_DOMAIN
    SSL_AUTO = program_dir + '/' + SSL_AUTO
    SCREENSHOT = program_dir + '/' + SCREENSHOT

if __name__ == '__main__':
    change_program_path()
    args = parse_options()
    if args.urls or args.url_file:
        url_list = parse_domain(args.urls, args.url_file)
        execute_commands(url_list, args.flag_no_nmap)
