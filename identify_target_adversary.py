#!/usr/bin/python3
import yara
import re
import argparse
import pathlib
import os
import shutil
import subprocess
import copy
import pprint

YARA_RULES_DIR = 'yara_rules'

def GetFilenameStem(filename):
    return pathlib.Path(filename).stem.lower()

def get_html_dir(target_dir):
    target_dir_pathlib = pathlib.Path(target_dir)
    search_str = '*_html'
    dir_list = [str(p) for p in target_dir_pathlib.glob(search_str) if os.path.isdir(p)]
    return dir_list

def exist_relative_pngfile(html_dir):
    s = re.search('(?P<prefix>[^/]+_)[0-9]*_html', html_dir)
    html_dir_path = pathlib.Path(html_dir)
    html_dir_parent = html_dir_path.parents[0]
    search_str = s.group('prefix') + '*.png'
    if len(sorted(html_dir_parent.glob(search_str))):
        return True
    else:
        return False

def sort_html_dir(dir_list):
    new_dir_list = []
    for dir in dir_list:
        '''
        if exist_relative_pngfile(dir):
            new_dir_list.append(dir)
        '''
        new_dir_list.append(dir)
    new_dir_list = sort_smartphone_pc_https_http(new_dir_list)
    return new_dir_list

def sort_smartphone_pc_https_http(dir_list):
    new_dir_list = []
    for dir in dir_list:
        if re.search('_smartphone_', dir):
            if re.search('https_', dir):
                new_dir_list.append(dir)
    for dir in dir_list:
        if re.search('_smartphone_', dir):
            if re.search('http_', dir):
                new_dir_list.append(dir)
    for dir in dir_list:
        if re.search('_pc_', dir):
            if re.search('https_', dir):
                new_dir_list.append(dir)
    for dir in dir_list:
        if re.search('_pc_', dir):
            if re.search('http_', dir):
                new_dir_list.append(dir)
    return new_dir_list

def get_file_glob(target_dir, search_str):
    target_dir_pathlib = pathlib.Path(target_dir)
    file_list = [str(p) for p in target_dir_pathlib.glob(search_str) if os.path.isfile(p)]
    return file_list

def yara_execute(target, rules):
    if isinstance(target, list):
        target_file_list = []
        for t in target:
            if os.path.isdir(t):
                target_dir_pathlib = pathlib.Path(t)
                target_file_list2 = [str(p) for p in target_dir_pathlib.glob('**/*') if os.path.isfile(p)]
                target_file_list.extend(target_file_list2)
            elif os.path.isfile(t):
                target_file_list.append(t)
    else:
        if os.path.isdir(target):
            target_dir_pathlib = pathlib.Path(target)
            target_file_list = [str(p) for p in target_dir_pathlib.glob('**/*') if os.path.isfile(p)]
        elif os.path.isfile(target):
            target_file_list = [target]
    matches_yara = []
    for target_file in target_file_list:
        try:
            matches = rules.match(target_file)
            if len(matches) > 0:
                matches_yara.extend(list(matches.keys()))
        except yara.libyara_wrapper.YaraMatchError:
            pass
    matches_yara = list(set(matches_yara))
    matches_yara.sort()
    return matches_yara

def import_yara_rules(yara_rules):
    global YARA_RULES_DIR
    if yara_rules is None:
        yara_rules = YARA_RULES_DIR
    filepaths={}
    if os.path.isdir(yara_rules):
        yara_rules_dir_pathlib = pathlib.Path(yara_rules)
        rules_file_list = [str(p) for p in yara_rules_dir_pathlib.glob('**/*') if os.path.isfile(p)]
        for rule_file in rules_file_list:
            namespace = GetFilenameStem(rule_file)
            filepaths[namespace] = rule_file
    elif os.path.isfile(yara_rules):
        namespace = GetFilenameStem(yara_rules)
        filepaths[namespace] = yara_rules
    rules = yara.compile(filepaths=filepaths)
    return rules

def change_yara_rules_global_path():
    global YARA_RULES_DIR
    program_dir = os.path.dirname(os.path.abspath(__file__))
    YARA_RULES_DIR = program_dir + '/' + YARA_RULES_DIR

def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', dest='target_dir', default='.', help='webpreserve directory')
    parser.add_argument('--yara_rules', dest='yara_rules', help='yara rule file or directory')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    change_yara_rules_global_path()
    rules = import_yara_rules(args.yara_rules)

    webpreserve_file_list = get_file_glob(args.target_dir, '*_webpreserve_*.txt')
    matches_yara = yara_execute(webpreserve_file_list, rules)

    html_dir_list = get_html_dir(args.target_dir)
    html_dir_list = sort_html_dir(html_dir_list)
    matches_yara.extend(yara_execute(html_dir_list, rules))

    matches_yara = list(set(matches_yara))
    matches_yara.sort()
    matches_yara = ','.join(matches_yara)
    print('yara matches:\t{}'.format(matches_yara))
