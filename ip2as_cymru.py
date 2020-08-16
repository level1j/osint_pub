#!/usr/bin/python3
import dns.resolver
import dns.reversename
import defang
import argparse
import pathlib
import tempfile
import os
import subprocess
import json
import pprint

def make_nc_argfile(target_ip_list):
    with tempfile.NamedTemporaryFile(mode='w', dir=os.getcwd(), prefix='.nccymru_', delete=False) as f:
        print('begin\nverbose', file=f)
        for ip in target_ip_list:
            print(ip, file=f)
        print('end', file=f)
    return f.name

def nc_cymru(target_file_name):
    WHOIS = 'whois.cymru.com'
    WHOIS_PORT = '43'
    target_file_path = pathlib.Path(target_file_name)
    output_file_path = pathlib.Path(target_file_name + '_r')
    with target_file_path.open(mode='r') as target_file_f:
        with output_file_path.open(mode='w') as output_file_f:
            # http://www.team-cymru.org/IP-ASN-mapping.html
            # We recommend the use GNU's version of netcat, not nc. (nc has been known to cause buffering problems with our server and will not always return the full output for larger IP lists). GNU netcat can be downloaded from http://netcat.sourceforge.net. This is the same as gnetcat in FreeBSD ports.
            # You need to official GNU netcat.
            proc = subprocess.run(['/bin/nc.traditional', WHOIS, WHOIS_PORT], stdin=target_file_f, stdout=output_file_f, stderr=subprocess.DEVNULL, shell=False)
    as_list = []
    with output_file_path.open(mode='r') as output_file_f:
        for as_information in output_file_f:
            as_information = as_information.strip().split('|')
            as_information = list(map(lambda x: x.strip(), as_information))
            if len(as_information) == 7:
                data = {'as': as_information[0], 'ip': as_information[1], 'bgpprefix': as_information[2], 'country': as_information[3], 'registry': as_information[4], 'allocatedday': as_information[5],'asname': as_information[6]}
                as_list.append(data)
        os.remove(target_file_name + '_r')
    return as_list

def ip2as_cymru(ip_list):
    BULK_NUMBER = 3000
    as_total_list = []
    flag_finish = False
    i = 0
    ip_total_number = len(ip_list)
    while True:
        if ip_total_number > BULK_NUMBER * (i + 1):
            target_ip_list = ip_list[BULK_NUMBER*i:BULK_NUMBER*(i+1)]
        else:
            target_ip_list = ip_list[BULK_NUMBER*i:]
            flag_finish = True
        target_file_name = make_nc_argfile(target_ip_list)
        as_list = nc_cymru(target_file_name)
        as_total_list.extend(as_list)
        os.remove(target_file_name)
        if flag_finish:
            break
        else:
            i = i + 1
    return as_total_list

def get_dns_from_ip(ip):
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.query(addr, 'PTR')
        return str(answers[0])
    except dns.resolver.NXDOMAIN:
        return None

def ip2dns(ip_list):
    dns_list = []
    for ip in ip_list:
        dns = get_dns_from_ip(ip)
        dns_list.append({'ip': ip, 'dns': dns})
    return dns_list

def merge_ip2as_ip2dns(as_list, dns_list):
    as_dns_list = []
    for a in as_list:
        for dns in dns_list:
            if a['ip'] == dns['ip']:
                a['dns'] = dns['dns']
                as_dns_list.append(a)
    return as_dns_list

def import_ip_file(ip_file):
    filepath = pathlib.Path(ip_file)
    with filepath.open(mode='r') as f:
        ip_list = []
        for ip in f:
            ip = ip.strip()
            if ip is not '' and ip not in ip_list:
                ip_list.append(ip)
    return ip_list

def output(as_list, output_tsv, output_json):
    if output_tsv:
        columns = ['ip', 'as', 'country', 'asname']
        print('\t'.join(columns))
        for as_information in as_list:
            output_string = ''
            for column in columns:
                output_string = output_string + as_information[column] + '\t'
            output_string = output_string[:-1]
            print(output_string)
    elif output_json:
        output_string = json.dumps(as_list)
        print(output_string)
    else:
        pprint.pprint(as_list)
    return

def rename_key_dns_ptr(as_dns_list):
    as_dns_list_new = []
    for as_dns in as_dns_list:
        as_dns['ptr'] = as_dns.pop('dns')
        as_dns_list_new.append(as_dns)
    return as_dns_list_new

def output2(as_dns_list, output_tsv, output_json):
    as_dns_list.sort(key=lambda x: x['ip'])
    as_dns_list = rename_key_dns_ptr(as_dns_list)
    if output_tsv:
        columns = ['ip', 'as', 'country', 'asname', 'ptr']
        print('\t'.join(columns))
        for as_information in as_list:
            output_string = ''
            for column in columns:
                if as_information[column] is None:
                    as_information[column] = 'None'
                output_string = output_string + as_information[column] + '\t'
            output_string = output_string[:-1]
            print(output_string)
    elif output_json:
        output_string = json.dumps(as_list)
        print(output_string)
    else:
        pprint.pprint(as_list)
    return

def parse_ip(ips, ip_file):
    ip_list = []
    if ips:
        ip_list.extend(ips.split(','))
    if ip_file:
        ip_list.extend(import_ip_file(ip_file))
    ip_list = list(set(ip_list))
    ip_list = list(map(lambda x: defang.refang(x), ip_list))
    return ip_list

def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', action='store', dest='ips', help='ip1[,ip2]')
    parser.add_argument('-f', '--file', action='store', dest='ip_file', help='ip list file')
    parser.add_argument('-t', '--tsv', action='store_true', dest='output_tsv', default=False, help='output tsv')
    parser.add_argument('-j', '--json', action='store_true', dest='output_json', default=False, help='output json')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_options()
    ip_list = parse_ip(args.ips, args.ip_file)
    as_list = ip2as_cymru(ip_list)
    #output(as_list, args.output_tsv, args.output_json)
    dns_list = ip2dns(ip_list)
    as_dns_list = merge_ip2as_ip2dns(as_list, dns_list)
    output2(as_dns_list, args.output_tsv, args.output_json)
