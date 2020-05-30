#!/usr/bin/python3
import defang
import tldextract
from urllib.parse import urlparse
from urllib.parse import urljoin
import requests
import selenium
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from bs4 import BeautifulSoup
import datetime
import time
from pytz import timezone
import pathlib
import re
import os
import sys
import subprocess
import argparse
import pprint

MODE_SMARTPHONE='MODE_SMARTPHONE'
#USERAGENT_SMARTPHONE='Mozilla/5.0 (iPhone; CPU OS 10_15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/14E304 Safari/605.1.15'
USERAGENT_SMARTPHONE='Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/81.0.4044.124 Mobile/15E148 Safari/604.1'
USERAGENT_PC='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0'
WGET_TIMEOUT=1
WGET_RETRY_NUMBER=2
WGET_MAX_FILE_SIZE='10m'
INTERESTING_EXTS = ['php', 'zip', 'gz', 'tgz', 'sh', 'asp', 'csv', 'log', '']

def get_now():
    d = datetime.datetime.now(timezone('UTC'))
    return d.strftime('%Y%m%d%H%M')

def get_domain_from_dns(dns):
    ext = tldextract.extract(dns)
    return ext.registered_domain

def get_domain_from_url(url):
    o = urlparse(url)
    hostname = o.hostname
    domain = get_domain_from_dns(o.hostname)
    return domain

def get_ext_from_url(url):
    o = urlparse(url)
    p = pathlib.Path(o.path)
    return p.suffix[1:]

def check_wget_log_file(filepath):
    with filepath.open(mode='r') as f:
        try:
            line = f.readline()
        except UnicodeDecodeError:
            return False
        s = re.match('--[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}--\s*[a-z]+:\/\/', line, re.IGNORECASE)
        if s:
            return True
    return False

def get_wget_log_file_list_from_dir(wget_log_dir):
    wget_log_list = []
    p = pathlib.Path(wget_log_dir)
    file_path_list = [p for p in p.glob('*') if os.path.isfile(p)]
    for filepath in file_path_list:
        if check_wget_log_file(filepath):
            wget_log_list.append(filepath.name)
    return wget_log_list

def get_wget_log_file_list(wget_log_list, wget_log_dir_list):
    wget_log_list_new = []
    if wget_log_list:
        wget_log_list_new.extend(wget_log_list.split(','))
    if wget_log_dir_list:
        for wget_log_dir in wget_log_dir_list.split(','):
            wget_log_list_new.extend(get_wget_log_file_list_from_dir(wget_log_dir))
    wget_log_list_new = list(set(wget_log_list_new))
    wget_log_list_new.sort()
    return wget_log_list_new

def get_link_dir_list_from_wget_log_file(wget_log_file):
    link_dir_list = []
    p = pathlib.Path(wget_log_file)
    with p.open(mode='r') as f:
        content = f.read()
        links_dir = re.findall('--[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}--\s*([a-z]+:\/\/.+\/)', content)
        link_dir_list.extend(links_dir)
    link_dir_list = list(set(link_dir_list))
    return link_dir_list

def check_url_in_domain_list(link, domain_list):
    domain_list_lower = list(map(lambda x: x.lower(), domain_list))
    link_domain = get_domain_from_url(link)
    if link_domain.lower() in domain_list_lower:
        return True
    else:
        return False

def get_recursive_parent_dir_urls(urls):
    url_parent_dir_list = []
    for url in urls:
        o = urlparse(url)
        if o.path != '/':
            p = pathlib.PurePosixPath(o.path)
            dir = ''
            for parent in reversed(p.parents):
                dir = dir + parent.name + '/'
                url_parent_dir_list.append(urljoin(url, dir))
    return url_parent_dir_list

def get_link_dir_list_from_wget_log_file_list(wget_log_file_list, domain_list):
    link_dir_list = []
    for wget_log_file in wget_log_file_list:
        link_dir_list.extend(get_link_dir_list_from_wget_log_file(wget_log_file))
    link_dir_list = list(set(link_dir_list))
    link_dir_list = [link_dir for link_dir in link_dir_list if check_url_in_domain_list(link_dir, domain_list)]
    link_dir_list.extend(get_recursive_parent_dir_urls(link_dir_list))
    link_dir_list = list(set(link_dir_list))
    link_dir_list.sort()
    return link_dir_list

def get_suffix_from_mode(mode):
    if mode == MODE_SMARTPHONE:
        suffix = 'smartphone'
    elif mode == MODE_PC:
        suffix = 'pc'
    else:
        suffix = ''
    return suffix

def find_or_define_wget_log_name(url, mode):
    suffix = get_suffix_from_mode(mode)
    o = urlparse(url)
    p = pathlib.Path('.')
    #filename_search = '**/' + o.scheme + '_' + o.hostname + '_' + suffix + '_' + '*' + '.html.log'
    filename_search = '**/' + o.scheme + '_*' + get_domain_from_url(url) + '_' + suffix + '_' + '*' + '.html.log'
    file_path_list = [p for p in p.glob(filename_search) if os.path.isfile(p)]
    if len(file_path_list) > 0:
        file_path_list.sort(reverse=True)
        wget_log = file_path_list[0]
    else:
        wget_log = o.scheme + '_' + o.hostname + '_' + suffix + '_' + get_now() + '.html.log'
    return wget_log

def find_or_define_wget_dir_name(url, mode):
    suffix = get_suffix_from_mode(mode)
    o = urlparse(url)
    p = pathlib.Path('.')
    #filename_search = '**/' + o.scheme + '_' + o.hostname + '_' + suffix + '_' + '*' + '_html'
    filename_search = '**/' + o.scheme + '_*' + get_domain_from_url(url) + '_' + suffix + '_' + '*' + '_html'
    dir_path_list = [p for p in p.glob(filename_search) if os.path.isdir(p)]
    if len(dir_path_list) > 0:
        dir_path_list.sort(reverse=True)
        wget_dir = dir_path_list[0]
    else:
        wget_dir = o.scheme + '_' + o.hostname + '_' + suffix + '_' + get_now() + '_html'
    return wget_dir

def find_or_define_wget_dir_log_name(url, mode):
    wget_dir = find_or_define_wget_dir_name(url, mode)
    wget_log = find_or_define_wget_log_name(url, mode)
    return wget_dir, wget_log

def save_html_bulk(link_list, useragent=USERAGENT_SMARTPHONE, mode=MODE_SMARTPHONE):
    file_exist = {}
    suffix = get_suffix_from_mode(mode)
    for url in link_list:
        o = urlparse(url)
        if o.hostname is None:
            continue
        s = o.scheme + '_' + o.hostname + '_' + suffix
        if s not in file_exist:
            wget_dir, wget_log = find_or_define_wget_dir_log_name(url, mode)
            file_exist[s] = {'wget_dir': wget_dir, 'wget_log': wget_log}
        dirname_html = file_exist[s]['wget_dir']
        filename_log = file_exist[s]['wget_log']
        subprocess.run(['wget', '-HpkK', '--no-check-certificate', '--content-on-error', '--server-response', '-a', filename_log, '-P', dirname_html, '-U', useragent, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url], stdin=subprocess.DEVNULL, shell=False)

def check_title_index(filepath):
    index_titles = ['index of', 'directory listing for']
    with filepath.open(mode='r', errors='backslashreplace') as f:
        try:
            content = f.read()
        except UnicodeDecodeError:
            print(filepath)
            return False
        soup = BeautifulSoup(content, 'lxml')
        if soup.find('title'):
            for index_title in index_titles:
                s = re.search(index_title, soup.title.string, re.IGNORECASE)
                if s:
                    return True
    return False

def get_wget_index_of_html_from_wget_archive():
    index_of_file_list = []
    p = pathlib.Path('.')
    file_path_list = [p for p in p.glob('**/index.*') if os.path.isfile(p)]
    for filepath in file_path_list:
        if check_title_index(filepath):
            index_of_file_list.append(str(filepath))
    return index_of_file_list

def check_interesting_url(link):
    if link.endswith('/'):
        return False
    #example: ?C=N;O=D ?C=M;O=A ?C=S;O=A ?C=D;O=A
    s = re.search('\?[^/]*$', link)
    if s:
        return False
    suffix = get_ext_from_url(link)
    if suffix.lower() in INTERESTING_EXTS:
        return True
    return False

def get_interseting_link_from_file(filepath):
    link_interesting = []
    p = pathlib.Path(filepath)
    with p.open(mode='r', errors='backslashreplace') as f:
        content = f.read()
        soup = BeautifulSoup(content, 'lxml')
        for x in soup.findAll('a'):
            try:
                href = x['href']
            except KeyError:
                pass
            if check_interesting_url(href):
                link_interesting.append(href)
    return link_interesting

def get_interesting_link_from_index_of_file_list(index_of_file_list):
    link_interesting = []
    for index_of_file in index_of_file_list:
        link_interesting.extend(get_interseting_link_from_file(index_of_file))
    link_interesting = list(set(link_interesting))
    return link_interesting

def output_list(any_list, title=None, file=sys.stderr):
    if file != sys.stderr:
        p = pathlib.Path(file)
        file = p.open(mode='a')
    if title is not None:
        print('{}:'.format(title), file=file)
    for l in any_list:
        print(l, file=file)
    print(file=file)
    if file != sys.stderr:
        file.close()

def output_status(str, file=sys.stderr):
    if file != sys.stderr:
        p = pathlib.Path(file)
        file = p.open(mode='a')
    print('{}'.format(str), file=file)
    if file != sys.stderr:
        file.close()

def parse_domain_list(domain_list):
    domain_list = domain_list.split(',')
    domain_list = list(map(lambda x: defang.refang(x), domain_list))
    domain_list = list(map(lambda x: get_domain_from_dns(x), domain_list))
    return domain_list

def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--wget-log', dest='wget_log_list', help='wget log file,wget log file2,...')
    parser.add_argument('-d', '--wget-log-dir', dest='wget_log_dir_list', help='dir(contains wget log file.),dir2,...')
    parser.add_argument(dest='domain_list', help='domain,domain2,...')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    domain_list = parse_domain_list(args.domain_list)
    log_file_name = 'dirlist_' + get_now() + '.log'
    output_status('Start scan for wget log file to list directory links')
    output_status('Start scan for wget log file to list directory links', file=log_file_name)
    wget_log_file_list = get_wget_log_file_list(args.wget_log_list, args.wget_log_dir_list)
    if len(wget_log_file_list) == 0:
        exit()
    link_dir_list = get_link_dir_list_from_wget_log_file_list(wget_log_file_list, domain_list)
    if len(link_dir_list) == 0:
        exit()
    output_list(link_dir_list, title='Targets')
    output_list(link_dir_list, title='Targets', file=log_file_name)
    output_status('Start download targets and check whether file is "Index of" or not')
    output_status('Start download targets and check whether file is "Index of" or not', file=log_file_name)
    save_html_bulk(link_dir_list, useragent=USERAGENT_SMARTPHONE, mode=MODE_SMARTPHONE)
    index_of_file_list = get_wget_index_of_html_from_wget_archive()
    if len(index_of_file_list) == 0:
        output_status('No "Index of" file')
        output_status('No "Index of" file', file=log_file_name)
        exit()
    output_list(index_of_file_list, title='Saved Index files')
    output_list(index_of_file_list, title='Saved Index files', file=log_file_name)
    link_interesting_list = get_interesting_link_from_index_of_file_list(index_of_file_list)
    if len(link_interesting_list) == 0:
        output_status('No interesting urls')
        output_status('No interesting urls', file=log_file_name)
        exit()
    output_list(link_interesting_list, title='Interesting urls')
    output_list(link_interesting_list, title='Interesting urls', file=log_file_name)
    output_status('Start download files for interesting urls')
    output_status('Start download files for interesting urls', file=log_file_name)
    save_html_bulk(link_interesting_list, useragent=USERAGENT_SMARTPHONE, mode=MODE_SMARTPHONE)
