#!/usr/bin/python3
#-------------------------------------------------------------------------------
# Updated:    2020/11/3
#-------------------------------------------------------------------------------
import defang
from urllib.parse import urlparse
import requests
import datetime
from pytz import timezone
import dateutil.parser
import argparse, configparser
import pathlib
import os, sys
import re
import pprint, json

REQ_TIMEOUT_SECONDS = 300
REQ_WAIT_RETRY_SECONDS = 1800
GET_TOP_UUID = 1

def str2date(s):
    return dateutil.parser.parse(s)

def get_validate_hostname(hostname):
    hostname = defang.refang(hostname)
    o = urlparse(hostname)
    if o.scheme == '':
        return hostname
    else:
        return o.hostname

def urlscan_search_api(hostname):
    URL = 'https://urlscan.io/api/v1/search/'
    params = {'q': hostname}
    while True:
        try:
            response = requests.get(URL, params=params, timeout=REQ_TIMEOUT_SECONDS)
            response.encoding = response.apparent_encoding
            break
        except:
            print('Request Timeout for {}'.format(URL))
            time.sleep(REQ_WAIT_RETRY_SECONDS)
    response_json = json.loads(response.text)
    return response_json['results']

def requests_get(url):
    while True:
        try:
            response = requests.get(url, timeout=REQ_TIMEOUT_SECONDS)
            response.encoding = response.apparent_encoding
            break
        except:
            print('Request Timeout for {}'.format(url))
            time.sleep(REQ_WAIT_RETRY_SECONDS)
    return response.text

def urlscan_result_api(uuid):
    url = 'https://urlscan.io/api/v1/result/' + uuid + '/'
    response_txt = requests_get(url)
    response_json = json.loads(response_txt)
    return response_json

def urlscan_response_req(hash):
    url = 'https://urlscan.io/responses/' + hash + '/'
    return requests_get(url)

def urlscan_search(hostname):
    urlscan_search_results = urlscan_search_api(hostname)
    urlscan_search_results = sorted(urlscan_search_results, key=lambda x: str2date(x['indexedAt']))
    urlscan_search_results = sorted(urlscan_search_results, key=lambda x: x['stats']['requests'], reverse=True)
    return urlscan_search_results

def urlscan_result(uuid):
    urlscan_result_result = urlscan_result_api(uuid)
    return urlscan_result_result

def urlscan_dom(url):
    urlscan_dom_result = requests_get(url)
    return urlscan_dom_result

def urlscan_response(hash):
    urlscan_response_result = urlscan_response_req(hash)
    return urlscan_response_result

def urlscan_screenshot(url):
    while True:
        try:
            response = requests.get(url, timeout=REQ_TIMEOUT_SECONDS)
            break
        except:
            print('Request Timeout for {}'.format(url))
            time.sleep(REQ_WAIT_RETRY_SECONDS)
    return response.content

def make_file_urlscan_search(hostname, urlscan_search_results):
    file_name = hostname + '_urlscan_search.txt'
    with open(file_name, 'w') as f:
        json.dump(urlscan_search_results, f, indent=2, ensure_ascii=False)

def make_file_urlscan_result(hostname, urlscan_result_result, uuid):
    file_name = hostname + '_urlscan_result.txt'
    urlscan_result_result['_result'] = 'https://urlscan.io/api/v1/result/' + uuid + '/'
    with open(file_name, 'w') as f:
        json.dump(urlscan_result_result, f, indent=2, ensure_ascii=False)

def make_file_urlscan_dom(hostname, urlscan_dom_result, domurl):
    file_name = hostname + '_urlscan_dom.txt'
    with open(file_name, 'w', encoding='utf_8') as f:
        f.write(urlscan_dom_result)
        f.write('\n')
        f.write(domurl)

def make_file_urlscan_response(hostname, urlscan_response_result, hash):
    file_name = hostname + '_urlscan_response.txt'
    url_ref = 'https://urlscan.io/responses/' + hash + '/'
    with open(file_name, 'w', encoding='utf_8') as f:
        f.write(urlscan_response_result)
        f.write('\n')
        f.write(url_ref)

def make_file_urlscan_screenshot(hostname, urlscan_screeshot_result, url):
    file_name = hostname + '_urlscan_screenshots.png'
    with open(file_name, 'wb') as f:
        f.write(urlscan_screeshot_result)
        f.write('\n'.encode(encoding='utf-8'))
        f.write(url.encode(encoding='utf-8'))

def get_now_with_sec():
    d = datetime.datetime.now(timezone('UTC'))
    return d.strftime('%Y%m%d%H%M%S')

def mkdir_chdir(cwd_dir):
    p = pathlib.Path(cwd_dir)
    p.mkdir()
    current_dir = pathlib.Path.cwd()
    os.chdir(cwd_dir)
    return os.path.abspath(current_dir), os.path.abspath(cwd_dir)

def get_urlscan_result(uuid, hostname):
    urlscan_result_result = urlscan_result(uuid)
    make_file_urlscan_result(hostname, urlscan_result_result, uuid)
    urlscan_dom_result = urlscan_dom(urlscan_result_result['task']['domURL'])
    make_file_urlscan_dom(hostname, urlscan_dom_result, urlscan_result_result['task']['domURL'])
    urlscan_response_result = urlscan_response(urlscan_result_result['data']['requests'][0]['response']['hash'])
    make_file_urlscan_response(hostname, urlscan_response_result, urlscan_result_result['data']['requests'][0]['response']['hash'])
    urlscan_screeshot_result = urlscan_screenshot(urlscan_result_result['task']['screenshotURL'])
    make_file_urlscan_screenshot(hostname, urlscan_screeshot_result, urlscan_result_result['task']['screenshotURL'])

def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', action='store', dest='hostname', help='hostname')
    parser.add_argument('--top', action='store', dest='top', type=int, default=GET_TOP_UUID, help='How many result?')
    args = parser.parse_args()
    return args

def main():
    args = parse_options()
    hostname = get_validate_hostname(args.hostname)
    previous_dir, cwd_dir = mkdir_chdir(hostname + '_urlscan_' + get_now_with_sec())
    urlscan_search_results = urlscan_search(hostname)
    make_file_urlscan_search(hostname, urlscan_search_results)
    for uuid in [d['_id'] for d in urlscan_search_results][0:args.top]:
        print('{} for {}'.format(uuid, hostname))
        previous_dir2, cwd_dir2 = mkdir_chdir(uuid)
        get_urlscan_result(uuid, hostname)
        os.chdir(previous_dir2)

if __name__ == '__main__':
    main()
