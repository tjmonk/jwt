#!/bin/sh

ssh-keygen -t rsa -b 4096 -m PEM -f private.key
ssh-keygen -f private.key -e -m PKCS8 > public.key
pubkey=`awk -v ORS='\\n' '1' public.key`
privkey=`awk -v ORS='\\n' '1' private.key`
