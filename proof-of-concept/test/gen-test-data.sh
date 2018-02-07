#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

PRIVATE_KEY_PASSWORD="qweASD123"
ENC_PASSWORD="qweASD123"

WORK_DIR="${SCRIPT_FOLDER}/tmp"
TEST_DIR="${WORK_DIR}/test-data"
KEYS_DIR="${WORK_DIR}/keys"

DATA_TO_BE_ENCRYPTED="Hello crypto World !!!"
DATA_FILE="${TEST_DIR}/cms-test-data.txt"
C_DATA_FILE="${SCRIPT_FOLDER}/test-data.c"

function prepare_work_dir() {
	if [ -f "${C_DATA_FILE}" ]; then
		rm "${C_DATA_FILE}"
	fi
	
	if [ -d "${WORK_DIR}" ]; then
		rm -rf "${WORK_DIR}"
	fi
	mkdir "${WORK_DIR}"
	mkdir "${KEYS_DIR}"
	mkdir "${TEST_DIR}"
}

function create_data_file() {
	echo "${DATA_TO_BE_ENCRYPTED}" > "${DATA_FILE}"
}

function __gen_key() {
	echo "---  Generate key : ${1} --- "
	virgil keygen -a "${1}" --private-key-password ${PRIVATE_KEY_PASSWORD} -o ${1}.key
	virgil key2pub -i ${1}.key -o ${1}.pub -p ${PRIVATE_KEY_PASSWORD}
}

function gen_keys() {
	pushd "${KEYS_DIR}"
		__gen_key bp256r1
		__gen_key bp384r1
		__gen_key bp512r1
		__gen_key secp192r1
		__gen_key secp224r1
		__gen_key secp256r1
		__gen_key secp384r1
		__gen_key secp521r1
		__gen_key secp192k1
		__gen_key secp224k1
		__gen_key secp256k1
		__gen_key curve25519
		__gen_key rsa3072
		__gen_key rsa4096
		__gen_key rsa8192
	popd
}

function __enc_one() {
	echo "Encrypt per one recipient. Key ${1}"
	virgil encrypt -i "${DATA_FILE}" -o "${TEST_DIR}/${1}.enc" pubkey:${1}:${1}
}

function enc_one_recipient() {
	pushd "${KEYS_DIR}"
		for i in *.pub; do
	    	[ -f "$i" ] || break
	    	__enc_one "$i"
		done
	popd
}

function enc_multiple_recipients() {
	echo "Encrypt per multiple recipients."
	
	local CMD="virgil encrypt -i ${DATA_FILE} -o ${TEST_DIR}/multiple.enc "
	
	pushd "${KEYS_DIR}"
		for i in *.pub; do
	    	[ -f "$i" ] || break
	    	CMD="${CMD} pubkey:${i}:${i}"
		done
		eval "${CMD}"
	popd
}

function password_encryption() {
	echo "---  Password encryption --- "
	virgil encrypt -i "${DATA_FILE}" -o "${TEST_DIR}/password.enc" password:"${ENC_PASSWORD}"
}

function create_test_file() {
	echo "Generate C file with test data."
	
	echo " " > "${C_DATA_FILE}"
	
	pushd "${TEST_DIR}"
		for i in *.enc; do
	    	[ -f "$i" ] || break
			xxd -i "${i}" >> "${C_DATA_FILE}"
			echo " " >> "${C_DATA_FILE}"
		done
	popd
}

function clean() {
	rm -rf "${WORK_DIR}"
}

prepare_work_dir
create_data_file
gen_keys
password_encryption
enc_one_recipient
enc_multiple_recipients
create_test_file
clean
