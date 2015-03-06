#!/bin/bash -e

# You will need ldapsearch installed ('ldap-utils' on ubuntu)

# an example ldap search to find possibly locked out users.
# adds a slew of options to make things work smoothly.

# use the full DN of user (CN=Doug Johnson,OU=Users,DC=ad1,DC=example,DC=com)
# or userprincipalname (djo@ad1.example.com)
# searches for: users + not disabled + lockouttime >= 1

LOGIN=$(whoami)
BINDPW=$(grabpw-nonl)
DOMAIN="ad1.example.com"

BINDDN="${LOGIN}@${DOMAIN}"
BASE=$(echo "dc=${DOMAIN}" | sed 's/\./,dc=/g')

# If you are on osx, gsed is a better option. In homebrew, of course.
if [ -e /usr/local/bin/gsed ]
then
  sed='gsed'
else
  sed='sed'
fi

ldapsearch  -l 1 \
            -s sub \
            -E pr=1000/noprompt \
            -LLL \
            -w ${BINDPW} \
            -xD ${BINDDN} \
            -h ${DOMAIN} \
            -b ${BASE} \
            '(&(objectclass=user)(objectclass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lockouttime>=1))' \
            samaccountname | \
            grep ^sAMA
