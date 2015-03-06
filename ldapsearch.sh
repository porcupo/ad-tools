#!/bin/bash

set -e

# removes the ridiculous formatting of ldapsearch

# if using homebrew, use gsed vs. osx's sed
if [ -e /usr/local/bin/gsed ]
then
  sed='gsed'
else
  sed='sed'
fi

domain=ad1.example.com
login=ro@${domain}
base="dc=ad1,dc=example,dc=com"

ldapsearch -l 1  -s sub -E pr=1000/noprompt -LLL -w $(grabpw-mcpadm) \
	   -xD ${login} -h ${domain} -b ${base} "$@" | \
           $sed -e ':a;N;$!ba;s/\n //g' | $sed -e '/^$/d' -e '/^#.*$/d'
echo
