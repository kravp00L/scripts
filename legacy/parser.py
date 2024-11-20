#!/usr/bin/env python3

import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument('-i','--input-file',type=str,required=True,help='Source grover input file')
parser.add_argument('-o','--output-file',type=str,required=True,help='Output file')
args = parser.parse_args()

try:
    with open(args.input_file,'r') as source_file:
        line_data = source_file.readlines()
except:
    print('Error opening file')
    exit(-1)
finally:
    source_file.close()

# extract all github usernames
# 1-39 characters, A-Z a-z 0-9 - but cannot start with dash
pattern = re.compile('[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}')
github_users = []
for line in line_data:
    username = line.split(',')[0]
    if len(username) <= 39:
        if not pattern.fullmatch(username) == None:
            if not username in github_users:
                print('[**] Adding username {}'.format(username))
                github_users.append(username)

# the results are not sorted by username
try:
    record_end_pattern = re.compile(',(t|f),\d$')
    line_number = 0
    previous_line = ''
    previous_username = ''
    with open(args.output_file,'w') as output_file:
        for line in line_data:
            # lines start with github username, 'typical' record over 300 characters
            # lines end with a comma,  t or f, another comma, then an integer
            current_username = line.split(',')[0].strip()
            valid_line_end = record_end_pattern.search(line)
            # case 1
            # write out valid lines with username and proper end of line
            if current_username in github_users and not valid_line_end == None:
                if not previous_line == '':
                    output_file.write(previous_line + '\n')
                    previous_line = ''
                output_file.write(line)
                previous_username = current_username
            # case 2
            # looking for newlines in password or bio field
            # valid start of line but invalid end of line
            # if the line end is incorrect, just concat to previous line
            elif current_username in github_users and valid_line_end == None:
                if not previous_line == '':
                    output_file.write(previous_line + '\n')
                    previous_line = ''
                previous_line = previous_line + line.strip('\n').strip()
                previous_username = current_username
            # case 3
            # identify lines that don't start with a github username
            elif not current_username in github_users:
                previous_line = previous_line + line.strip('\n').strip()
            # case 4
            # write out the header row
            elif 'github_user,repository,credential' in line:
                output_file.write(line)
            # should NOT get here, but print to show outliers
            else:
                print('[**] Debug: Line {} outside defined case {}'.format(line_number,line))
                previous_line = ''
            line_number = line_number + 1
            print('[**] Debug: Processing input file line {}: field 1 {}'.format(line_number,current_username))
except Exception as e:
    print('Exception message: {}'.format(e))
    exit(-1)
finally:
    output_file.close()