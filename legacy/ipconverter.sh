#!/bin/bash
#printf "DEBUG: Input is "$1"\n"
IFS='.'
read -r o1 o2 o3 o4 <<< $1
value=$((o1 * 256 ** 3 + o2 * 256 ** 2 + o3 * 256 + o4))
printf "IP address info:\n"
printf "Dotted decimal: %s\n"  "$o1.$o2.$o3.$o4"
printf "Decimal: %d\n" $value
printf "Hex: %X\n" $value
