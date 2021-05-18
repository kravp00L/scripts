import argparse
import csv
import xml.etree.ElementTree as et

parser = argparse.ArgumentParser()
parser.add_argument('-i','--input-file',type=str,required=True,help='Source Google Vault XML metadata file')
parser.add_argument('-o','--output-file',type=str,required=True,help='Output CSV file')
args = parser.parse_args()

root = et.parse(args.input_file).getroot()
# XML source structure
# Root > Batch > Documents > Document > Files > File > ExternalFile
# Looking for Document.DocID, ExternalFile.Filename, ExternalFile.FileHash
output_list = []
for stuff in root.findall('Batch/Documents/*'):
    doc_id = stuff.attrib['DocID']
    for otherstuff in stuff.findall('./Files/File/ExternalFile'):
        file_name = otherstuff.attrib['FileName']
        file_hash = otherstuff.attrib['Hash']
    output_list.append([doc_id,file_hash,file_name])
    print(f'{doc_id},{file_hash},{file_name}')

# Write out to CSV
columns = ['docid','hash','filename']
try:
    with open(args.output_file,'w') as outfile:
        writer = csv.writer(outfile, delimiter=',')
        writer.writerow(columns)
        for entry in output_list:
            writer.writerow(entry)
except IOError as e:
    print('IO Error. Message: {}'.format(e))
except Exception as e:
    print('I\'ve got a bad feeling about this.')
    print('Error message: {}'.format(e))
finally:
    outfile.close()