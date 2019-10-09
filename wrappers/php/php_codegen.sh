rm -rf VirgilCrypto
for project in phe foundation
do
	rm -rf $project/src
	rm -rf $project/extension
	find ../../codegen/generated/$project -type f -name "php_module_*" -delete
done

cd ../..
./codegen.sh

for project in phe foundation
do
	for dir in extension src
	do
		cp -R wrappers/php/VirgilCrypto/$project/$dir/ wrappers/php/$project/$dir
	done
done