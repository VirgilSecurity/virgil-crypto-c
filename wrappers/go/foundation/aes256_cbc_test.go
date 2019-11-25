//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package foundation

import (
	b64 "encoding/base64"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestNewAes256Cbc(t *testing.T) {
	aes256Cbc := NewAes256Cbc()

	assert.NotNil(t, aes256Cbc)
}

func TestAes256Cbc_Encrypt(t *testing.T) {
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_IV)
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	expectedEncryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_ENCRYPTED_DATA)

	aes256Cbc := NewAes256Cbc()
	aes256Cbc.SetKey(key)
	aes256Cbc.SetNonce(nonce)

	encryptedData, err := aes256Cbc.Encrypt(data)

	assert.Nil(t, err)
	assert.NotNil(t, encryptedData)
	assert.Equal(t, expectedEncryptedData, encryptedData)
}

func TestAes256Cbc_Encrypt_WithCipher(t *testing.T) {
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_IV)
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	expectedEncryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_ENCRYPTED_DATA)

	aes256Cbc := NewAes256Cbc()
	aes256Cbc.SetKey(key)
	aes256Cbc.SetNonce(nonce)

	aes256Cbc.StartEncryption()
	blockLen := int(aes256Cbc.GetBlockLen())

	var updateData []byte
	for startIndex := 0; startIndex < len(data); {
		var endIndex = startIndex + blockLen
		block := data[startIndex:endIndex]
		updateData = append(updateData, aes256Cbc.Update(block)...)

		startIndex += blockLen
	}
	finishData, err := aes256Cbc.Finish()
	assert.Nil(t, err)

	encryptedData := append(updateData, finishData...)

	assert.NotNil(t, encryptedData)
	assert.Equal(t, expectedEncryptedData, encryptedData)
}

func TestAes256Cbc_Decrypt(t *testing.T) {
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_IV)

	aes256Cbc := NewAes256Cbc()
	aes256Cbc.SetKey(key)
	aes256Cbc.SetNonce(nonce)

	decryptedData, err := aes256Cbc.Decrypt(encryptedData)

	assert.Nil(t, err)
	assert.NotNil(t, decryptedData)
	assert.True(t, reflect.DeepEqual(expectedDecryptedData, decryptedData))
}

func TestAes256Cbc_Decrypt_WitCipher(t *testing.T) {
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_CBC_IV)

	aes256Cbc := NewAes256Cbc()
	aes256Cbc.SetKey(key)
	aes256Cbc.SetNonce(nonce)

	aes256Cbc.StartDecryption()
	updateData := aes256Cbc.Update(encryptedData)
	finishData, err := aes256Cbc.Finish()
	assert.Nil(t, err)

	decryptedData := append(updateData, finishData...)

	assert.NotNil(t, decryptedData)
	assert.True(t, reflect.DeepEqual(expectedDecryptedData, decryptedData))
}

func TestAes256Cbc_GetNonceLen(t *testing.T) {
	aes256Cbc := NewAes256Cbc()
	assert.Equal(t, uint32(TEST_AES256_CBC_NONCE_LEN), aes256Cbc.GetNonceLen())
}

func TestAes256Cbc_GetKeyLen(t *testing.T) {
	aes256Cbc := NewAes256Cbc()
	assert.Equal(t, uint32(TEST_AES256_CBC_KEY_LEN), aes256Cbc.GetKeyLen())
}

func TestAes256Cbc_GetKeyBitLen(t *testing.T) {
	aes256Cbc := NewAes256Cbc()
	assert.Equal(t, uint32(TEST_AES256_CBC_KEY_BIT_LEN), aes256Cbc.GetKeyBitlen())
}

func TestAes256Cbc_GetBlockLen(t *testing.T) {
	aes256Cbc := NewAes256Cbc()
	assert.Equal(t, uint32(TEST_AES256_CBC_BLOCK_LEN), aes256Cbc.GetBlockLen())
}
