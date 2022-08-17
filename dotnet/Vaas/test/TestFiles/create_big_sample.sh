#!/bin/sh

if [ $# -ne 1 ]
then
	echo "Usage: create_big_sample <MB>" 
	exit 1
fi

mkdir big 
if [ $? -ne 0 ]
then
	echo Directory big already exists
	exit 1
fi

dd if=/dev/urandom of=big/big.dat bs=1M count=$1
curl https://secure.eicar.org/eicar.com.txt -o big/eicar.com.txt
zip -0 -r big big/

rm -rf big
