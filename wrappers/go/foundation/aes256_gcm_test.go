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

func TestNewAes256Gcm(t *testing.T) {
    aes256Gcm := NewAes256Gcm()

    assert.NotNil(t, aes256Gcm)
}

func TestAes256Gcm_AuthEncrypt(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	authData, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_AUTH_DATA)
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_NONCE)
	expectedOut, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_AUTH_OUT)
	expectedTag, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_AUTH_TAG)

	aes256Gcm := NewAes256Gcm()
	aes256Gcm.SetKey(key)
	aes256Gcm.SetNonce(nonce)

	out, tag, err := aes256Gcm.AuthEncrypt(data, authData)

	assert.Nil(t, err)
	assert.Equal(t, expectedOut, out)
	assert.Equal(t, expectedTag, tag)
}

func TestAes256Gcm_Encrypt(t *testing.T) {
    key, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_KEY)
    nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_NONCE)
    data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
    expectedEncryptedData := []byte(TEST_AES256_GCM_ENCRYPTED_DATA)

    aes256Gcm := NewAes256Gcm()
    aes256Gcm.SetKey(key)
    aes256Gcm.SetNonce(nonce)

    encryptedData, err := aes256Gcm.Encrypt(data)

	assert.Nil(t, err)
    assert.NotNil(t, encryptedData)
    assert.True(t, reflect.DeepEqual(expectedEncryptedData, encryptedData))
}

func TestAes256Gcm_Encrypt_WithCipher(t *testing.T) {
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_NONCE)
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	expectedEncryptedData := []byte(TEST_AES256_GCM_ENCRYPTED_DATA)

	aes256Gcm := NewAes256Gcm()
	aes256Gcm.SetKey(key)
	aes256Gcm.SetNonce(nonce)

	aes256Gcm.StartDecryption()
	updateData := aes256Gcm.Update(data)
	finishData, err := aes256Gcm.Finish()
	assert.Nil(t, err)

	encryptedData := append(updateData, finishData...)

	assert.NotNil(t, encryptedData)
	assert.True(t, reflect.DeepEqual(expectedEncryptedData, encryptedData))
}

func TestAes256Gcm_Decrypt(t *testing.T) {
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_NONCE)

	aes256Gcm := NewAes256Gcm()
	aes256Gcm.SetKey(key)
	aes256Gcm.SetNonce(nonce)

	decryptedData, err := aes256Gcm.Decrypt(encryptedData)

	assert.Nil(t, err)
	assert.NotNil(t, decryptedData)
	assert.True(t, reflect.DeepEqual(expectedDecryptedData, decryptedData))
}

func TestAes256Gcm_Decrypt_WitCipher(t *testing.T) {
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	key, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_KEY)
	nonce, _ := b64.StdEncoding.DecodeString(TEST_AES256_GCM_NONCE)

	aes256Gcm := NewAes256Gcm()
	aes256Gcm.SetKey(key)
	aes256Gcm.SetNonce(nonce)

	aes256Gcm.StartDecryption()
	updateData := aes256Gcm.Update(encryptedData)
	finishData, err := aes256Gcm.Finish()
	assert.Nil(t, err)

	decryptedData := append(updateData, finishData...)

	assert.NotNil(t, decryptedData)
	assert.True(t, reflect.DeepEqual(expectedDecryptedData, decryptedData))
}

func TestAes256Gcm_GetNonceLen(t *testing.T) {
    aes256Gcm := NewAes256Gcm()
    assert.Equal(t, TEST_AES256_GCM_NONCE_LEN, aes256Gcm.GetNonceLen())
}

func TestAes256Gcm_GetKeyLen(t *testing.T) {
    aes256Gcm := NewAes256Gcm()
    assert.Equal(t, TEST_AES256_GCM_KEY_LEN, aes256Gcm.GetKeyLen())
}

func TestAes256Gcm_GetKeyBitLen(t *testing.T) {
    aes256Gcm := NewAes256Gcm()
    assert.Equal(t, TEST_AES256_GCM_KEY_BIT_LEN, aes256Gcm.GetKeyBitlen())
}

func TestAes256Gcm_GetBlockLen(t *testing.T) {
    aes256Gcm := NewAes256Gcm()
    assert.Equal(t, TEST_AES256_GCM_BLOCK_LEN, aes256Gcm.GetBlockLen())
}

func TestAes256Gcm_GetAuthTagLen(t *testing.T) {
	aes256Gcm := NewAes256Gcm()
	assert.Equal(t, TEST_AES256_GCM_AUTH_TAG_LEN, aes256Gcm.GetAuthTagLen())
}
