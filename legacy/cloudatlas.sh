
#!/bin/bash
#####################################################
# CloudAtlas v0.1 by kravp00L
#
# Recon tool to identify services associated with 
# 'cloud' services
#####################################################


if [ "$1" != "" ]; then
    echo 'Finding information on '$1
else
    echo 'Please provide the IP address to examine.'
    echo 'Usage: cloudatlas.sh <IP address>'
    exit
fi

host=`dig +short -x "$1"`
if [ "$host" != "" ]; then
    echo '[+] IP address maps to '$host
else
    echo '[-] No PTR record found for '$1
fi

raw="$(wget -nv https://$1 2>&1)"
# echo $raw
id=$( echo $raw | sed 's/`//g' | sed "s/'//g" | cut -d " " -f 5 )
echo "[+] "$1 is associated with $id
