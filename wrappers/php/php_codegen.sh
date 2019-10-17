rm -rf VirgilCrypto
for project in phe foundation
do
	for dir in extension src vendor
	do
		rm -rf $project/$dir
	done

	rm $project/composer.json
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

	cp wrappers/php/VirgilCrypto/$project/composer.json wrappers/php/$project/composer.json
done

rm -rf wrappers/php/VirgilCrypto