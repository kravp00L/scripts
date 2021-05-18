#!/usr/bin/env python3
"""
    Author : David Mashburn (dmashburn@salesforce.com)
    Description : Script for bulk whois using RIPE API
"""

# Imports
import argparse
import datetime
import requests
import sys
import time

# Variables
# These are the defined REST API URLs for the RIRs
# RIPE DNS chain
ripe_dns_chain_api = 'https://stat.ripe.net/data/dns-chain/data.json?resource='
# RIPE geolocation
ripe_geo_api = 'https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource='
# RIPE whois
ripe_whois_api = 'https://stat.ripe.net/data/whois/data.json?resource='

# Accept arguments for the script
parser = argparse.ArgumentParser('Investigate IP address information')
# Make a group of mutually exclusive options
group = parser.add_mutually_exclusive_group()
# Positional argument for single hostname or IP address
group.add_argument('-t',
                    '--target-host',
                    type=str,
                    help='IP address for evaluation')
# accept file with list of IP addresses or hosts
group.add_argument('-i',
                    '--input-file',                    
                    type=str,
                    help='Filename with list of IP addresses')
parser.add_argument('-s',
                    '--sleep-time',
                    default=5,
                    help='Seconds to sleep between API calls to avoid throttling')
# Toggle extra checks on
parser.add_argument('-c',
                    '--compact-output',
                    action="store_true",
                    default=False,
                    help='Run the checks beyond the whois')
# Toggle extra checks on
parser.add_argument('-a',
                    '--all-checks',
                    action="store_true",
                    default=False,
                    help='Run the checks beyond the whois')
# Toggle verbosity on
parser.add_argument('-v',
                    '--verbose',                    
                    action="store_true",
                    default=False,
                    help='Increases the verbosity of the script output')
# Parse all these arguments
args = parser.parse_args()

#Functions
# write out verbose messages
def log_verbose_output(message):
    print(''.join(['[**] ', message]))

# Call to RIPE API for DNS info
def get_ripe_dns_chain(ip_address):
    try:
        if args.verbose:
            log_verbose_output(
            'Calling RIPE DNS chain API for {}'.format(ip_address))
        json_result = requests.get(''.join([ripe_dns_chain_api,ip_address]))
    except requests.ConnectionError as e:
        print('ERROR: Connection error to RIPE DNS chain API')
        print('Error message: {}'.format(e))
    except requests.Timeout as e:
        print('ERROR: Timeout connecting to RIPE DNS chain API')
        print('Error message: {}'.format(e))
    finally:
        return json_result.json()

# Parse and print DNS chain info
def parse_ripe_dns(json_data, ip_address):
    print('[****] DNS information for {}'.format(ip_address))
    try:
        dns_dict = json_data['data']
        for nameserver in dns_dict['authoritative_nameservers']:
            print('[*] Nameserver:  {}'.format(nameserver))    
        for host in dns_dict['forward_nodes']:
            print('[*] Reverse DNS lookup:  {}'.format(host))
        for host in dns_dict['reverse_nodes']:
            print('[*] Forward DNS lookup:  {}'.format(host))
    except Exception as e:
        print('Error while parsing RIPE abuse data')
        print('Error message: {}'.format(e))

# Call to RIPE API for geolocation
def get_ripe_geo_ip(ip_address):
    try:
        if args.verbose:
            log_verbose_output(
            'Calling RIPE geolocation API for {}'.format(ip_address))
        json_result = requests.get(''.join([ripe_geo_api,ip_address]))      
    except requests.ConnectionError as e:
        print('ERROR: Connection error to RIPE geolocation API')
        print('Error message: {}'.format(e))
    except requests.Timeout as e:
        print('ERROR: Timeout connecting to RIPE geolocation API')
        print('Error message: {}'.format(e))
    finally:        
        return json_result.json()

# Parse and print geolocation data
def parse_ripe_geoip(json_data, ip_address):
    print('[****] IP Geolocation information for {}'.format(ip_address))
    try:
        location_dict = json_data['data']['located_resources'][0].get('locations')[0]
        print('[*] Country:  {}'.format(location_dict.get('country')))
        print('[*] City:  {}'.format(location_dict.get('city')))
        print('[*] Latitude:  {}'.format(location_dict.get('latitude')))
        print('[*] Longitude:  {}'.format(location_dict.get('longitude')))
    except Exception as e:
        print('Error while parsing RIPE geoip data')
        print('Error message: {}'.format(e))

# Call to RIPE API for whois
def get_ripe_whois(ip_address):
    try:
        if args.verbose:
            log_verbose_output(
            'Calling RIPE whois API for {}'.format(ip_address))
        json_result = requests.get(''.join([ripe_whois_api,ip_address]))  
    except requests.ConnectionError as e:
        print('ERROR: Connection error to RIPE whois API')
        print('Error message: {}'.format(e))
    except requests.Timeout as e:
        print('ERROR: Timeout connecting to RIPE whois API')
        print('Error message: {}'.format(e))
    finally:
        return json_result.json()

# Parse and print whois information
def parse_ripe_whois(json_data, ip_address):
    # data comes back as dict/list/list/dict
    # define fields we want in the list and pull only those
    data_fields = ['CustName','Address','City','PostalCode',
        'Country','OrgName','Organization','NetRange','CIDR']
    print('[****] IP whois information for {}'.format(ip_address))
    try:
        records = json_data['data']['records']
        for nested_list in records:
            for entry in nested_list:
                if entry['key'] in data_fields:
                    print('[*] {}: {}'.format(entry.get('key'),entry.get('value')))
    except Exception as e:
        print('Error while parsing RIPE whois data')
        print('Error message: {}'.format(e))

# Take targets and convert to list
# Handles case of multiple comma separated entries via -t
def create_ip_list():
    ip_list = []
    if args.target_host:
        if args.verbose:
            log_verbose_output(
            'Processing command line entries {}'.format(args.target_host))
        ip_list = args.target_host.split(',')
    elif args.input_file:
        if args.verbose:
            log_verbose_output(
            'Processing entries in file {}'.format(args.input_file))
            try:
                with open(args.input_file,'r') as f:
                    for line in f:
                        ip_list.append(line)
            except IOError as e:
                print(''.join(['Error opening file ',args.input_file]))
                print('Error message: {}'.format(e))
            finally:
                f.close()
    return ip_list

# Program execution starts here
def main():
    print('[****] Program started at {}'.format(datetime.datetime.now()))
    # Check for the required arguments
    sleepy_time = int(args.sleep_time)

    if args.verbose:
        log_verbose_output('Verbose mode enabled')

    # whether file or on command line, create list of ips
    target_list = create_ip_list()
    for input_value in target_list:
         # Call whois API
        whois_json = get_ripe_whois(input_value.strip())
        # Need this check because the 500 error happens...
        if whois_json['status'].lower() == 'error' or whois_json['status_code'] == 500:
            print('Error code in results from call to RIPE whois')
        else:
            parse_ripe_whois(whois_json, input_value.strip())
        # pause to keep from getting throttled
        time.sleep(sleepy_time)

        if args.all_checks:
            # Call DNS chain API
            dns_json = get_ripe_dns_chain(input_value.strip())
            parse_ripe_dns(dns_json, input_value.strip())
            # pause to keep from getting throttled
            time.sleep(sleepy_time)

            # Call geolocation API
            geoip_json = get_ripe_geo_ip(input_value.strip())
            parse_ripe_geoip(geoip_json, input_value.strip())
            # pause to keep from getting throttled
            time.sleep(sleepy_time)

if __name__ == '__main__':
    main()