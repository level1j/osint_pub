#!/usr/bin/python3
import defang
import selenium
from selenium import webdriver
from urllib.parse import urlparse
import time
import os
import sys
import subprocess
import psutil
import datetime
from pytz import timezone
import argparse
import pprint

USERAGENT_SMARTPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1'
USERAGENT_PC = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36 Edg/84.0.522.50'
USERAGENT = USERAGENT_SMARTPHONE
WIDTH_SMARTPHONE = 414
HEIGHT_SMARTPHONE = 896
WIDTH_PC = 1295
HEIGHT_PC = 695
WIDTH = WIDTH_SMARTPHONE
HEIGHT = HEIGHT_SMARTPHONE
ACCPET_LANGUAGE_SMARTPHONE = 'ja-jp'
ACCPET_LANGUAGE_PC = 'ja,en-US;q=0.7,en;q=0.3'
ACCPET_LANGUAGE = ACCPET_LANGUAGE_SMARTPHONE
GECKODRIVER_LOG='geckodriver.log'
MODE_SMARTPHONE='smartphone'
MODE_PC='pc'
MODE = MODE_SMARTPHONE
SELENIUM_WEBDRIVER=''
SELENIUM_WEBDRIVER_FIREFOX='firefox'
SELENIUM_WEBDRIVER_CHROME='chrome'
SELENIUM_SLEEP_TIME = 15
SELENIUM_SLEEP_TIME_PER_HEIGHT = 5
HEIGHT_ADD_SELENIUM_SLEEP = 2000
SELENIUM_TIMEOUT_RESPONSE_FIREFOX = 10
SELENIUM_TIMEOUT_RUNSCRIPT_FIREFOX = 10
ERROR_MSG = [
    'unknown error: net::ERR_NAME_NOT_RESOLVED',
    'Reached error page: about:neterror'
]
WGET_TIMEOUT = 10
WGET_RETRY_NUMBER = 2
WGET_MAX_FILE_SIZE = '10m'
PROXY=None
PYTHON3='/usr/bin/python3'
SCREENSHOTPY='screenshot.py'

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
        newurl = 'http://' + url
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

def get_save_filename(url, mode=MODE):
    suffix = mode
    o = urlparse(url)
    return o.scheme + '_' + o.hostname + '_' + suffix + '_' + get_now()

def wevdriver_initialize_firefox():
    options = selenium.webdriver.firefox.options.Options()
    options.add_argument('--headless')
    profile = webdriver.FirefoxProfile()
    profile.set_preference('general.useragent.override', USERAGENT)
    profile.set_preference('http.response.timeout', SELENIUM_TIMEOUT_RESPONSE_FIREFOX)
    profile.set_preference('dom.max_script_run_time', SELENIUM_TIMEOUT_RUNSCRIPT_FIREFOX)
    profile.set_preference('intl.accept_languages', ACCPET_LANGUAGE)
    profile.accept_untrusted_certs = True
    if PROXY is None:
        driver = webdriver.Firefox(firefox_profile=profile, firefox_options=options)
    else:
        firefox_capabilities = selenium.webdriver.DesiredCapabilities.FIREFOX
        firefox_capabilities['marionette'] = True
        firefox_capabilities['proxy'] = {
            'proxyType': 'MANUAL',
            'httpProxy': PROXY,
            'ftpProxy': PROXY,
            'sslProxy': PROXY
        }
        driver = webdriver.Firefox(firefox_profile=profile, firefox_options=options, capabilities=firefox_capabilities)
    driver.set_window_size(WIDTH, HEIGHT)
    return driver

def wevdriver_initialize_chrome():
    options = selenium.webdriver.chrome.options.Options()
    options.add_argument('--headless')
    options.add_argument('user-agent=' + USERAGENT)
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-extensions')
    options.add_argument('--allow-running-insecure-content')
    options.add_argument('--disable-web-security')
    options.set_capability('unhandledPromptBehavior', 'accept')
    if PROXY is not None:
        options.add_argument('--proxy-server=%s' % PROXY)
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(WIDTH, HEIGHT)
    return driver

def save_screenshot_common(driver, url, filename_screenshot, filename_page_source):
    driver.get(url)
    page_width = driver.execute_script('return document.body.scrollWidth')
    if WIDTH > page_width:
        page_width = WIDTH
    page_height = driver.execute_script('return document.body.scrollHeight')
    if HEIGHT > page_height:
        page_height = HEIGHT
    driver.set_window_size(page_width, page_height)
    sleep_time = SELENIUM_SLEEP_TIME + ((int(page_height / HEIGHT_ADD_SELENIUM_SLEEP)) * SELENIUM_SLEEP_TIME_PER_HEIGHT)
    time.sleep(sleep_time)
    with open(filename_page_source, mode='w') as f:
        f.write(driver.page_source)
    #driver.save_screenshot(filename_screenshot)
    el = driver.find_element_by_tag_name('body')
    el.screenshot(filename_screenshot)
    return

def is_excepted_WebDriverException(e):
    flag_em = False
    for em in ERROR_MSG:
        if em in e.msg:
            flag_em = True
    return flag_em

def save_screenshot_firefox(url, filename_screenshot, filename_page_source):
    try:
        driver = wevdriver_initialize_firefox()
        save_screenshot_common(driver, url, filename_screenshot, filename_page_source)
    except (selenium.common.exceptions.TimeoutException) as e:
        print('Exception(save_screenshot_firefox1): {} for {}'.format(e, url), file=sys.stderr)
    except (selenium.common.exceptions.WebDriverException) as e:
        print('Exception(save_screenshot_firefox2): {} for {}'.format(e, url), file=sys.stderr)
        if not is_excepted_WebDriverException(e):
            driver.save_screenshot(filename_screenshot)
    finally:
        driver.close()
        driver.quit()
        remove_geckodriver_log()
    return

def save_screenshot_chrome(url, filename_screenshot, filename_page_source):
    try:
        driver = wevdriver_initialize_chrome()
        save_screenshot_common(driver, url, filename_screenshot, filename_page_source)
    except (selenium.common.exceptions.TimeoutException) as e:
        print('Exception(save_screenshot_chrome1): {} for {}'.format(e, url), file=sys.stderr)
    except (selenium.common.exceptions.WebDriverException) as e:
        print('Exception(save_screenshot_chrome2): {} for {}'.format(e, url), file=sys.stderr)
        if not is_excepted_WebDriverException(e):
            driver.save_screenshot(filename_screenshot)
    except (selenium.common.exceptions.UnexpectedAlertPresentException) as e:
        print('Exception(save_screenshot_chrome3): {} for {}'.format(e, url), file=sys.stderr)
    finally:
        driver.close()
        driver.quit()
    return

def save_screenshot(url, mode=MODE):
    filename_screenshot = get_save_filename(url, mode) + '.png'
    filename_page_source = get_save_filename(url, mode) + '.selenium.html'
    if SELENIUM_WEBDRIVER == SELENIUM_WEBDRIVER_FIREFOX:
        save_screenshot_firefox(url, filename_screenshot, filename_page_source)
    elif SELENIUM_WEBDRIVER == SELENIUM_WEBDRIVER_CHROME:
        save_screenshot_chrome(url, filename_screenshot, filename_page_source)
    else:
        save_screenshot_firefox(url, filename_screenshot, filename_page_source)

def get_robotstxt_from_url(url):
    o = urlparse(url)
    o_bot = o._replace(path='/robots.txt')
    url_robot = o_bot.geturl()
    return url_robot

def save_html(url, mode=MODE):
    dirname_html = get_save_filename(url, mode) + '_html'
    filename_log = get_save_filename(url, mode) + '.html.log'
    url_robot = get_robotstxt_from_url(url)
    if PROXY is None:
        subprocess.run(['wget', '-HpkK', '--no-check-certificate', '--content-on-error', '--server-response', '-o', filename_log, '-P', dirname_html, '-U', USERAGENT, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url], stdin=subprocess.DEVNULL, shell=False)
        subprocess.run(['wget', '-pkK', '--no-check-certificate', '--content-on-error', '--server-response', '-a', filename_log, '-P', dirname_html, '-U', USERAGENT, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url_robot], stdin=subprocess.DEVNULL, shell=False)
    else:
        http_proxy = 'http_proxy=' + PROXY
        https_proxy = 'https_proxy=' + PROXY
        subprocess.run(['wget', '-e', http_proxy, '-e', https_proxy, '-HpkK', '--no-check-certificate', '--content-on-error', '--server-response', '-o', filename_log, '-P', dirname_html, '-U', USERAGENT, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url], stdin=subprocess.DEVNULL, shell=False)
        subprocess.run(['wget', '-e', http_proxy, '-e', https_proxy, '-pkK', '--no-check-certificate', '--content-on-error', '--server-response', '-a', filename_log, '-P', dirname_html, '-U', USERAGENT, '--prefer-family=IPv4', '-e', 'robots=off', '-T', str(WGET_TIMEOUT), '-t', str(WGET_RETRY_NUMBER), '-Q', WGET_MAX_FILE_SIZE, url_robot], stdin=subprocess.DEVNULL, shell=False)

def set_browser_env(mode):
    global USERAGENT
    global WIDTH
    global HEIGHT
    global ACCPET_LANGUAGE
    if mode == MODE_SMARTPHONE:
        USERAGENT = USERAGENT_SMARTPHONE
        WIDTH = WIDTH_SMARTPHONE
        HEIGHT = HEIGHT_SMARTPHONE
        ACCPET_LANGUAGE = ACCPET_LANGUAGE_SMARTPHONE
    elif mode == MODE_PC:
        USERAGENT = USERAGENT_PC
        WIDTH = WIDTH_PC
        HEIGHT = HEIGHT_PC
        ACCPET_LANGUAGE = ACCPET_LANGUAGE_PC
    return

def set_proxy(proxy):
    global PROXY
    PROXY = proxy
    return

def remove_geckodriver_log():
    os.remove(GECKODRIVER_LOG)

def get_pid_list(psname):
    try:
        return list(map(int, subprocess.check_output(['pidof', psname]).split()))
    except subprocess.CalledProcessError as e:
        print('Error Exception: {}'.format(e), flush=True)
        return []

def exist_cmdline(pid, s):
    try:
        p = psutil.Process(pid)
        for c in p.cmdline():
            if s.upper() in c.upper():
                return True
    except psutil.AccessDenied as e:
        print('Error Exception: {}'.format(e), flush=True)
        return False
    return False

def find_screenshotpy():
    python3_pid_list = get_pid_list(PYTHON3)
    screenshotpy_pid_list = list(filter(lambda x: exist_cmdline(x, SCREENSHOTPY), python3_pid_list))
    # 1 is myself
    if len(screenshotpy_pid_list) == 1:
        return True
    else:
        return False

def kill_firefox():
    if find_screenshotpy():
        subprocess.run(['killall', '/usr/lib/firefox/firefox'], stdin=subprocess.DEVNULL, shell=False)

def parse_options():
    parser = argparse.ArgumentParser(description='take screenshot')
    parser.add_argument(dest='url', help='URL')
    parser.add_argument('--up', '--useragent-pc', dest='useragent_pc', default=USERAGENT_PC, help='User-Agent for pc mode')
    parser.add_argument('--us', '--useragent-smartphone', dest='useragent_smartphone', default=USERAGENT_SMARTPHONE, help='User-Agent for smartphone mode')
    parser.add_argument('-p', '--pc', action='store_true', dest='pc_mode', default=False, help='pc mode')
    parser.add_argument('-s', '--smartphone', action='store_true', dest='smartphone_mode', default=False, help='smart phone mode')
    parser.add_argument('--save-html', action='store_true', dest='flag_save_html', default=False, help='save html')
    parser.add_argument('--http-https', action='store_true', dest='flag_http_https', default=False, help='screenshot with both http and https')
    parser.add_argument('--proxy', dest='proxy', help='proxy ex 10.0.1.97:3128')
    parser.add_argument('--kill-firefox', action='store_true', default=False, dest='kill_firefox', help='kill firefox process related to screenshot.py')
    parser.add_argument('--webdriver-firefox', action='store_true', default=False, dest='webdriver_firefox', help='use firefox as webdriver')
    parser.add_argument('--webdriver-chrome', action='store_true', default=False, dest='webdriver_chrome', help='use chrome as webdriver')
    args = parser.parse_args()
    global SELENIUM_WEBDRIVER
    if args.webdriver_firefox:
        SELENIUM_WEBDRIVER = SELENIUM_WEBDRIVER_FIREFOX
    elif args.webdriver_chrome:
        SELENIUM_WEBDRIVER = SELENIUM_WEBDRIVER_CHROME
    else:
        SELENIUM_WEBDRIVER = SELENIUM_WEBDRIVER_CHROME
    return args

def main():
    args = parse_options()
    if args.kill_firefox:
        kill_firefox()
    url = get_validate_url(args.url)
    schemes = [get_scheme(url)]
    if args.flag_http_https:
        if 'http' in schemes:
            schemes.append('https')
        elif 'https' in schemes:
            schemes.append('http')
    for scheme in schemes:
        url = change_scheme(url, scheme)
        if args.proxy:
            set_proxy(args.proxy)
        if args.smartphone_mode:
            mode = MODE_SMARTPHONE
            set_browser_env(mode)
            save_screenshot(url, mode)
            if args.flag_save_html:
                save_html(url, mode)
        if args.pc_mode:
            mode = MODE_PC
            set_browser_env(mode)
            save_screenshot(url, mode)
            if args.flag_save_html:
                save_html(url, mode)

if __name__ == '__main__':
    main()
