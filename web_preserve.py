#!/usr/bin/python3
import defang
import tldextract
import dns.resolver
from urllib.parse import urlparse
import argparse
import pprint
import re
import datetime
from pytz import timezone
import dateutil.parser
import ipaddress
import pathlib
import json
import subprocess
import os
import sys
import psutil
import shutil

IP2AS_CYMRU = 'ip2as_cymru.py'
RDAP_AUTO = 'rdap_wrapper.py'
WHOIS_DOMAIN = 'whois_domain.py'
SSL_AUTO = 'ssl_wrapper.py'
SCREENSHOT = 'screenshot.py'
DIRLIST4WGETLOG = 'dirlist4wgetlog.py'
ADMINFINDER = 'adminfinder.py'
IDENTIFY_TARGET_ADVERSARY = 'identify_target_adversary.py'
OPENVPN_VPNGATE_EC2 = 'openvpn_vpngate_ec2.py'
FLAG_OPENVPN = False

def get_now():
    d = datetime.datetime.now(timezone('UTC'))
    return d.strftime('%Y%m%d%H%M')

def get_now_with_sec():
    d = datetime.datetime.now(timezone('UTC'))
    return d.strftime('%Y%m%d%H%M%S')

def get_validate_url(url):
    url = defang.refang(url)
    o = urlparse(url)
    if o.path == '/':
        url = url.rstrip('/')
    if o.scheme == '':
        newurl = 'https://' + url
        class bcolors:
            WARNING = '\033[93m'
            ENDC = '\033[0m'
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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        print(e)
        return '-'

def is_ipaddress(str):
    try:
        ipaddress.ip_address(str)
        return True
    except ValueError:
        return False

def parse_url(url):
    url = get_validate_url(url)
    o = urlparse(url)
    scheme = o.scheme
    hostname = o.hostname
    path = o.path
    if path == '/':
        path = ''
    if not is_ipaddress(hostname):
        domain = get_domain_from_dns(hostname)
        ip = get_ip_from_dns(hostname)
    else:
        domain = '-'
        ip = hostname
    return url, scheme, hostname, domain, path, ip

def mkdir_chdir_start(hostname):
    cwd_dir = hostname + '_' + get_now_with_sec()
    p = pathlib.Path(cwd_dir)
    p.mkdir()
    current_dir = pathlib.Path.cwd()
    os.chdir(cwd_dir)
    return current_dir, cwd_dir

def mkdir_chdir_end(dir):
    os.chdir(dir)
    return

def create_log_file(hostname):
    log_file_name = hostname + '_webpreserve_' + get_now() + '.txt'
    p = pathlib.Path(log_file_name)
    return p.open(mode='w'), log_file_name

def close_log_file(file_f):
    file_f.close()
    return

def exist_filepath(filepath):
    p = pathlib.Path(filepath)
    if p.exists():
        return True
    else:
        return False

def exist_openvpn_vpngate_ec2():
    return exist_filepath(OPENVPN_VPNGATE_EC2)

def exist_openvpn():
    if shutil.which('openvpn') is not None:
        return True
    else:
        return False

def check_openvpn():
    if FLAG_OPENVPN and exist_openvpn() and exist_openvpn_vpngate_ec2():
        return True
    else:
        return False

def get_pid_list(psname, args=None):
    pid_list = []
    try:
        pid_list = list(map(int, subprocess.check_output(["pidof", psname]).split()))
    except subprocess.CalledProcessError as e:
        print('Exception: {}'.format(e))
    if args is not None:
        pid_list_new = []
        for pid in pid_list:
            try:
                p = psutil.Process(pid)
                cmdline = p.cmdline()
                for c in cmdline[1:]:
                    if args in c:
                        pid_list_new.append(pid)
            except psutil.AccessDenied as e:
                print('Exception: {}'.format(e))
        pid_list = pid_list_new
    return pid_list

def execute_commands(url_list, flag_no_nmap, proxy):
    global IP2AS_CYMRU
    global RDAP_AUTO
    global WHOIS_DOMAIN
    global SSL_AUTO
    global SCREENSHOT
    for url in url_list:
        url, scheme, hostname, domain, path, ip = parse_url(url)
        previous_dir, cwd_dir = mkdir_chdir_start(hostname)
        log_file_f, log_file_name = create_log_file(hostname)
        print('url\tscheme\thostname\tdomain\tpath\tip', file=log_file_f, flush=True)
        print('{}\t{}\t{}\t{}\t{}\t{}'.format(url, scheme, hostname, domain, path, ip), file=log_file_f, flush=True)
        if check_openvpn():
            pid_list = get_pid_list('openvpn')
            if len(pid_list) > 0:
                print(file=log_file_f, flush=True)
                subprocess.run(['python3', OPENVPN_VPNGATE_EC2, '-k'], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
        if ip != '-':
            print(file=log_file_f, flush=True)
            subprocess.run(['python3', IP2AS_CYMRU, '-t', '-i', ip], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            if scheme == 'https':
                print(file=log_file_f, flush=True)
                subprocess.run(['python3', SSL_AUTO, '-t', '-s', hostname], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
        if domain != '-':
            print(file=log_file_f, flush=True)
            subprocess.run(['python3', RDAP_AUTO, '-t', '-d', domain], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            print(file=log_file_f, flush=True)
            subprocess.run(['python3', WHOIS_DOMAIN, '-t', '-d', domain], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
        if ip != '-':
            if check_openvpn():
                pid_list = get_pid_list('openvpn')
                if len(pid_list) == 0:
                    print(file=log_file_f, flush=True)
                    subprocess.run(['python3', OPENVPN_VPNGATE_EC2], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            print(file=log_file_f, flush=True)
            if proxy is None:
                subprocess.run(['python3', SCREENSHOT, '-p', '-s', '--save-html', url], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            else:
                subprocess.run(['python3', SCREENSHOT, '-p', '-s', '--save-html', '--proxy', proxy, url], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            print(file=log_file_f, flush=True)
            subprocess.run(['python3', DIRLIST4WGETLOG, '-d', '.', domain], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            p = pathlib.Path(ADMINFINDER)
            if p.exists() :
                print(file=log_file_f, flush=True)
                subprocess.run(['python3', ADMINFINDER, url], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            if check_openvpn():
                pid_list = get_pid_list('python3', args='web_preserve.py')
                if len(pid_list) == 1:
                    print(file=log_file_f, flush=True)
                    subprocess.run(['python3', OPENVPN_VPNGATE_EC2, '-k'], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
            if not flag_no_nmap:
                nmap_save_file(ip)
                #pass
            #just in case
            if check_openvpn():
                pid_list = get_pid_list('python3', args='web_preserve.py')
                if len(pid_list) == 1:
                    print(file=log_file_f, flush=True)
                    subprocess.run(['python3', OPENVPN_VPNGATE_EC2, '-k'], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
        print(file=log_file_f, flush=True)
        subprocess.run(['python3', IDENTIFY_TARGET_ADVERSARY, '-d', '.'], stdin=subprocess.DEVNULL, stdout=log_file_f, stderr=log_file_f, shell=False)
        close_log_file(log_file_f)
        mkdir_chdir_end(previous_dir)

def nmap_save_file(ip):
    filename = ip + '_nmap_' + get_now() + '.txt'
    subprocess.run(['nmap', '-Pn', '-sV', '--script=safe', '-T4', '-F', '-oN', filename, ip], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, shell=False)
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

def parse_urls(urls, url_file):
    url_list = []
    if urls:
        url_list.extend(urls.split(','))
    if url_file:
        url_list.extend(import_domain_file(url_file))
    url_list = list(map(lambda x: get_validate_url(x), url_list))
    url_list = list(set(url_list))
    return url_list

def parse_options():
    global FLAG_OPENVPN
    parser = argparse.ArgumentParser(description='Execute ip2as,whois_domain,rdap_wrapper,ssl_wrapper,screenshot')
    parser.add_argument('-u', '--url', dest='urls', help='url1[,url2]')
    parser.add_argument('-f', '--file', action='store', dest='url_file', help='url list file')
    parser.add_argument('--no-nmap', action='store_true', dest='flag_no_nmap', default=False, help='disable nmap')
    parser.add_argument('-v', '--openvpn', action='store_true', dest='flag_openvpn', default=FLAG_OPENVPN, help='use vpn')
    parser.add_argument('--proxy-screenshot', dest='proxy', default=None, help='proxy only for screenshot.py. ex 10.0.1.97:3128')
    args = parser.parse_args()
    FLAG_OPENVPN = args.flag_openvpn
    return args

def change_program_path():
    global IP2AS_CYMRU
    global RDAP_AUTO
    global WHOIS_DOMAIN
    global SSL_AUTO
    global SCREENSHOT
    global DIRLIST4WGETLOG
    global IDENTIFY_TARGET_ADVERSARY
    global OPENVPN_VPNGATE_EC2
    global ADMINFINDER
    program_dir = os.path.dirname(os.path.abspath(__file__))
    IP2AS_CYMRU = program_dir + '/' + IP2AS_CYMRU
    RDAP_AUTO = program_dir + '/' + RDAP_AUTO
    WHOIS_DOMAIN = program_dir + '/' + WHOIS_DOMAIN
    SSL_AUTO = program_dir + '/' + SSL_AUTO
    SCREENSHOT = program_dir + '/' + SCREENSHOT
    DIRLIST4WGETLOG = program_dir + '/' + DIRLIST4WGETLOG
    IDENTIFY_TARGET_ADVERSARY = program_dir + '/' + IDENTIFY_TARGET_ADVERSARY
    OPENVPN_VPNGATE_EC2 = program_dir + '/' + OPENVPN_VPNGATE_EC2
    ADMINFINDER = program_dir + '/' + ADMINFINDER

def main():
    change_program_path()
    args = parse_options()
    if args.urls or args.url_file:
        url_list = parse_urls(args.urls, args.url_file)
        execute_commands(url_list, args.flag_no_nmap, args.proxy)

if __name__ == '__main__':
    main()
