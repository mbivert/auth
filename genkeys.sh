#!/bin/sh

set -x

if ! which openssl >/dev/null; then
	echo 'openssl(1)' not found 1>&2
	exit 1
fi

priv=private.pem
pub=public.pem

# NOTE: -noout removes paramaters from output file (...)
echo 'Generating private key:' $priv
openssl ecparam -name prime256v1 -genkey -noout -out $priv

echo 'Generating public key: ' $pub
openssl ec -in $priv -pubout > $pub 2>/dev/null

