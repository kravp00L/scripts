#!/usr/bin/env python3
"""
    Author: David Mashburn (dmashburn@salesforce.com)
    Overview: This script takes Google Apps JSON logs exported from Splunk
    and parses them into a suitable CSV format.
"""
import argparse
import csv
import json

parser = argparse.ArgumentParser()
parser.add_argument('-i','--input-file',type=str,required=True,help='Source JSON log file')
parser.add_argument('-o','--output-file',type=str,required=True,help='Output file')
args = parser.parse_args()

data_fields = ['doc_id', 'doc_type', 'doc_title', 'visibility', 'owner']
output_list = []
processed_lines = 0
lines_with_errors = 0
try:
    with open(args.input_file,'r') as source_file:
        for line_data in source_file:
            line_json = json.loads(line_data)
            output_dict = {}
            output_dict['ts'] = line_json['rawtext']['id']['time']
            try:
                output_dict['ip']= line_json['rawtext']['ipAddress']
            except:
                output_dict['ip']= "N/A"
            output_dict['email'] = line_json['rawtext']['actor']['email']
            output_dict['profileid'] = line_json['rawtext']['actor']['profileId']
            for item in line_json['rawtext']['events']:
                output_dict['name'] = item['name']
                output_dict['type'] = item['type']
                for param in item['parameters']:
                    if param['name'] in data_fields:
                        thiskey = param['name']
                        output_dict[thiskey] = param['value']
                output_list.append(output_dict)
            processed_lines += 1
except Exception as e:
    print('Something\'s not right')
    print('Error message: {}'.format(e))
    lines_with_errors += 1
finally:
    source_file.close()

print('Lines processed: {}'.format(str(processed_lines)))
print('Lines with errors: {}'.format(str(lines_with_errors)))

# Write out to CSV
columns = ['ts', 'ip', 'email', 'profileid', 'name', 'type', 'doc_id', 'doc_type', 'doc_title', 'visibility', 'owner']
output_lines = 0
try:
    with open(args.output_file,'w') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=columns)
        writer.writeheader()
        for entry in output_list:
            writer.writerow(entry)
            output_lines += 1
except IOError as e:
    print('IO Error. Message: {}'.format(e))
except Exception as e:
    print('I\'ve got a bad feeling about this.')
    print('Error message: {}'.format(e))
finally:
    outfile.close()
print('Entries in the list: {}'.format(str(len(output_list))))
print('Lines written to CSV: {}'.format(str(output_lines)))