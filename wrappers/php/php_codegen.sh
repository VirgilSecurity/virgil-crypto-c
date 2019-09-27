rm -rf VirgilCrypto
find ../../codegen/generated/phe -type f -name "php_module_*" -delete
find ../../codegen/generated/foundation -type f -name "php_module_*" -delete
cd ../..
./codegen.sh