#!/bin/bash

FILES=*
for f in $FILES
do
    f2=${f::-4}
    echo "Processing $f2..."

    openssl x509 -inform DER -in $f -outform PEM -out $f2.pem
    if [ $? -eq 0 ]; then
        echo OK
    else
        openssl x509 -in $f -outform PEM -out $f2.pem
        if [ $? -eq 0 ]; then
            echo OK
        else
            rm $f2.pem
        fi
    fi
done
