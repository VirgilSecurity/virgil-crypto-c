#!/bin/bash

rm -rf VirgilCryptoWrapper/src
rm -rf VirgilCryptoWrapper/vendor
rm -rf VirgilCryptoWrapper/extensions

for project in phe foundation ratchet pythia
do
	find ../../codegen/generated/$project -type f -name "php_module_*" -delete
done

cd ../..
./codegen.sh