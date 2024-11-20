#!/usr/bin/env python3

import argparse
import json
import xml.etree.ElementTree as ET
import re

parser = argparse.ArgumentParser()
parser.add_argument('-i','--input-file',type=str,required=True,help='Source input file')
parser.add_argument('-o','--output-file',type=str,required=True,help='Output file')
args = parser.parse_args()

# xml needs the caption= and class= XML attributes extracted
def parse_xml(xml_text):
    return_data = ''
    try:
        root = ET.fromstring(str(xml_text.replace(' :',' ')))
        nodes = root.findall('.//connection')
        for node in nodes:
            if 'caption' in node.attrib.keys():
                return_data = return_data + f",caption={node.attrib['caption']}"
            if 'class' in node.attrib.keys():
                return_data = return_data + f",class={node.attrib['class']}"
    except Exception as e:
        print(f'Exception: {e}')
    return return_data

# Extract the site and xml JSON values
# site goes directly into a field
try:
    with open(args.output_file,'w') as output_file:
        with open(args.input_file,'r') as source_file:
            for source_line in source_file:
                line = json.loads(source_line)
                site_name = line['site']
                parsed_values = parse_xml(line['xml'])
                output_file.write(site_name + parsed_values + '\n')
except Exception as e:
    print(f'Exception: {e}')
    exit(-1)
finally:
    source_file.close()
    output_file.close()