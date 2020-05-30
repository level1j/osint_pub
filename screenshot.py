#!/usr/bin/python3
import defang
import selenium
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from urllib.parse import urlparse
import os
import sys
import subprocess
import datetime
from pytz import timezone
import argparse

#USERAGENT_SMARTPHONE='Mozilla/5.0 (iPhone; CPU OS 10_15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/14E304 Safari/605.1.15'
USERAGENT_SMARTPHONE='Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/81.0.4044.124 Mobile/15E148 Safari/604.1'
USERAGENT_PC='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0'
SMARTPHONE_WIDTH=375
SMARTPHONE_HEIGHT=812
GECKODRIVER_LOG='geckodriver.log'
MODE_SMARTPHONE='MODE_SMARTPHONE'
MODE_PC='MODE_PC'
SELENIUM_TIMEOUT_RESPONSE=1
SELENIUM_TIMEOUT_RUNSCRIPT=5
WGET_TIMEOUT=10
WGET_RETRY_NUMBER=2
WGET_MAX_FILE_SIZE='10m'

def get_now():
    d = datetime.datetime.now(timezone('UTC'))
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

def get_scheme(url):
    o = urlparse(url)
    return o.scheme

def change_scheme(url, scheme_modified):
    o = urlparse(url)
    o_new = o._replace(scheme=scheme_modified)
    return o_new.geturl()

def get_save_filename(url, mode):
    if mode == MODE_SMARTPHONE:
        suffix = 'smartphone'
    elif mode == MODE_PC:
        suffix = 'pc'
    else:
        suffix = ''
    o = urlparse(url)
    return o.scheme + '_' + o.hostname + '_' + suffix + '_' + get_now()

def wevdriver_initialize(useragent, mode=MODE_SMARTPHONE):
    options = Options()
    options.add_argument('--headless')
    profile = webdriver.FirefoxProfile()
    profile.set_preference('general.useragent.override', useragent)
    profile.set_preference('http.response.timeout', SELENIUM_TIMEOUT_RESPONSE)
    profile.set_preference('dom.max_script_run_time', SELENIUM_TIMEOUT_RUNSCRIPT)
    profile.accept_untrusted_certs = True
    driver = webdriver.Firefox(firefox_profile=profile, firefox_options=options)
    if mode == MODE_SMARTPHONE:
        driver.set_window_size(SMARTPHONE_WIDTH, SMARTPHONE_HEIGHT)
    return driver

def save_screenshot(url, useragent, mode=MODE_SMARTPHONE):
    filename_screenshot = get_save_filename(url, mode) + '.png'
    try:
        driver = wevdriver_initialize(useragent, mode)
        driver.get(url)
        el = driver.find_element_by_tag_name('body')
        el.screenshot(filename_screenshot)
        driver.close()
        remove_geckodriver_log()
    except (selenium.common.exceptions.TimeoutException, selenium.common.exceptions.WebDriverException) as e:
        print('Exception: {} for {}'.format(e, url), file=sys.stderr)
    return

def get_robotstxt_from_url(url):
    o = urlparse(url)
    o_bot = o._replace(path='/robots.txt')
    url_robot = o_bot.geturl()
    return url_robot

def save_html(url, useragent, mode=MODE_SMARTPHONE):
    dirname_html = get_save_filename(url, mode) + '_html'
    filename_log = get_save_filename(url, mode) + '.html.log'
    subprocess.run(['wget', '-HpkK', '--no-check-certificate', '--content-on-error', '--server-response', '-o', filename_log, '-P', dirname_html, '-U', useragent, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url], stdin=subprocess.DEVNULL, shell=False)
    url_robot = get_robotstxt_from_url(url)
    subprocess.run(['wget', '-HpkK', '--no-check-certificate', '--content-on-error', '--server-response', '-a', filename_log, '-P', dirname_html, '-U', useragent, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url_robot], stdin=subprocess.DEVNULL, shell=False)

def get_useragent(mode, useragent):
    if mode == MODE_SMARTPHONE:
        ua = USERAGENT_SMARTPHONE
    elif mode == MODE_PC:
        ua = USERAGENT_PC
    if useragent:
        ua = useragent
    return useragent

def remove_geckodriver_log():
    os.remove(GECKODRIVER_LOG)

def parse_options():
    parser = argparse.ArgumentParser(description='take screenshot')
    parser.add_argument(dest='url', help='URL')
    parser.add_argument('--up', '--useragent-pc', dest='useragent_pc', default=USERAGENT_PC, help='User-Agent for pc mode')
    parser.add_argument('--us', '--useragent-smartphone', dest='useragent_smartphone', default=USERAGENT_SMARTPHONE, help='User-Agent for smartphone mode')
    parser.add_argument('-p', '--pc', action='store_true', dest='pc_mode', default=False, help='pc mode')
    parser.add_argument('-s', '--smartphone', action='store_true', dest='smartphone_mode', default=False, help='smart phone mode')
    parser.add_argument('--save-html', action='store_true', dest='flag_save_html', default=False, help='save html')
    parser.add_argument('--http-https', action='store_true', dest='flag_http_https', default=False, help='screenshot with both http and https')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    url = get_validate_url(args.url)
    schemes = [get_scheme(url)]
    if args.flag_http_https:
        if 'http' in schemes:
            schemes.append('https')
        elif 'https' in schemes:
            schemes.append('http')
    for scheme in schemes:
        url = change_scheme(url, scheme)
        if args.smartphone_mode:
            mode = MODE_SMARTPHONE
            useragent_smartphone = get_useragent(mode, args.useragent_smartphone)
            save_screenshot(url, useragent_smartphone, mode)
            if args.flag_save_html:
                save_html(url, useragent_smartphone, mode)
        if args.pc_mode:
            mode = MODE_PC
            useragent_pc = get_useragent(mode, args.useragent_pc)
            save_screenshot(url, useragent_pc, mode)
            if args.flag_save_html:
                save_html(url, useragent_pc, mode)
