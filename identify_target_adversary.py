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

def get_file(target_dir, search_str):
    target_dir_pathlib = pathlib.Path(target_dir)
    file_list = [str(p) for p in target_dir_pathlib.glob(search_str) if os.path.isfile(p)]
    return file_list

def get_dir(target_dir, search_str):
    target_dir_pathlib = pathlib.Path(target_dir)
    dir_list = [str(p) for p in target_dir_pathlib.glob(search_str) if os.path.isdir(p)]
    return dir_list

def get_html(html_dir_list):
    target_file_list = []
    for t in html_dir_list:
        if os.path.isdir(t):
            target_dir_pathlib = pathlib.Path(t)
            target_file_list2 = [str(p) for p in target_dir_pathlib.glob('**/*') if os.path.isfile(p)]
            target_file_list.extend(target_file_list2)
        elif os.path.isfile(t):
            target_file_list.append(t)
    return target_file_list

def get_match_rule_name(matches):
    rule_name_list_all = []
    for yara_name,v in matches.items():
        rule_name_list = [d.get('rule') for d in v]
        rule_name_list_all.extend(list(set(rule_name_list)))
    return rule_name_list_all

def yara_execute(target_file_list, rules):
    matches_yara = []
    matches_rule = []
    for target_file in target_file_list:
        try:
            matches = rules.match(target_file)
            if len(matches) > 0:
                matches_yara.extend(list(matches.keys()))
                matches_rule.extend(get_match_rule_name(matches))
        except yara.libyara_wrapper.YaraMatchError:
            pass
    matches_yara = list(set(matches_yara))
    matches_yara.sort()
    matches_rule = list(set(matches_rule))
    matches_rule.sort()
    return matches_yara, matches_rule

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
    parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='print also rule name')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_options()
    change_yara_rules_global_path()
    rules = import_yara_rules(args.yara_rules)

    webpreserve_file_list = get_file(args.target_dir, '*_webpreserve_*.txt')
    matches_yara, matches_rule = yara_execute(webpreserve_file_list, rules)

    html_dir_list = get_dir(args.target_dir,  '*_html')
    html_list = get_html(html_dir_list)
    html_list.extend(get_file(args.target_dir, '*.selenium.html'))
    html_list.extend(get_file(args.target_dir, '**/*_urlscan_*'))

    matches_yara_2, matches_rule_2 = yara_execute(html_list, rules)
    matches_yara.extend(matches_yara_2)
    matches_yara = list(set(matches_yara))
    matches_yara.sort()
    matches_yara = ','.join(matches_yara)
    print('yara matches:\t{}'.format(matches_yara))

    matches_rule.extend(matches_rule_2)
    matches_rule = list(set(matches_rule))
    matches_rule.sort()
    matches_rule = ','.join(matches_rule)
    if args.verbose:
        print('rule matches:\t{}'.format(matches_rule))
