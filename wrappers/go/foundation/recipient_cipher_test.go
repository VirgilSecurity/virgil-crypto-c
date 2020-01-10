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
	"testing"
)

func TestNewRecipientCipher(t *testing.T) {
	recipientCipher := NewRecipientCipher()

	assert.NotNil(t, recipientCipher)
}

func TestRecipientCipher_Encrypt_ED25519(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	recipientId := []byte{0x01, 0x02, 0x03}

	recipientCipher := NewRecipientCipher()
	ed := NewEd25519()
	err := ed.SetupDefaults()
	assert.Nil(t, err)

	privateKey, err := ed.GenerateKey()
	assert.Nil(t, err)

	// Encrypt
	extractedPublicKey, err := privateKey.ExtractPublicKey()
	assert.Nil(t, err)

	recipientCipher.AddKeyRecipient(recipientId, extractedPublicKey)
	recipientCipher.CustomParams().AddData([]byte("VIRGIL-DATA-SIGNER-ID"), []byte("VIRGIL-DATA-SIGNER-ID"))
	recipientCipher.CustomParams().AddData([]byte("VIRGIL-DATA-SIGNATURE"), []byte("VIRGIL-DATA-SIGNATURE"))

	err = recipientCipher.StartEncryption()
	assert.Nil(t, err)

	messageInfo := recipientCipher.PackMessageInfo()
	assert.NotNil(t, messageInfo)

	processEncryptionData, err := recipientCipher.ProcessEncryption(data)
	assert.Nil(t, err)
	assert.NotNil(t, processEncryptionData)

	finishEncryptionData, err := recipientCipher.FinishEncryption()
	assert.Nil(t, err)
	assert.NotNil(t, finishEncryptionData)

	encryptedData := append(append(messageInfo, processEncryptionData...), finishEncryptionData...)

	// Decrypt
	cipher := NewRecipientCipher()
	err = cipher.StartDecryptionWithKey(recipientId, privateKey, []byte{})
	assert.Nil(t, err)

	processDecryptionData, err := cipher.ProcessDecryption(encryptedData)
	assert.Nil(t, err)
	assert.NotNil(t, processDecryptionData)

	finishDecryptionData, err := cipher.FinishDecryption()
	assert.Nil(t, err)
	assert.NotNil(t, finishDecryptionData)

	decryptedData := append(processDecryptionData, finishDecryptionData...)
	assert.Equal(t, data, decryptedData)
}

func TestRecipientCipher_Encrypt_RSA(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	recipientId := []byte{0x01, 0x02, 0x03}

	recipientCipher := NewRecipientCipher()
	rsa := NewRsa()
	err := rsa.SetupDefaults()
	assert.Nil(t, err)

	privateKey, err := rsa.GenerateKey(2048)
	assert.Nil(t, err)

	// Encrypt
	extractedPublicKey, err := privateKey.ExtractPublicKey()
	assert.Nil(t, err)

	recipientCipher.AddKeyRecipient(recipientId, extractedPublicKey)
	recipientCipher.CustomParams().AddData([]byte("VIRGIL-DATA-SIGNER-ID"), []byte("VIRGIL-DATA-SIGNER-ID"))
	recipientCipher.CustomParams().AddData([]byte("VIRGIL-DATA-SIGNATURE"), []byte("VIRGIL-DATA-SIGNATURE"))

	err = recipientCipher.StartEncryption()
	assert.Nil(t, err)

	messageInfo := recipientCipher.PackMessageInfo()
	assert.NotNil(t, messageInfo)

	processEncryptionData, err := recipientCipher.ProcessEncryption(data)
	assert.Nil(t, err)
	assert.NotNil(t, processEncryptionData)

	finishEncryptionData, err := recipientCipher.FinishEncryption()
	assert.Nil(t, err)
	assert.NotNil(t, finishEncryptionData)

	encryptedData := append(append(messageInfo, processEncryptionData...), finishEncryptionData...)

	// Decrypt
	cipher := NewRecipientCipher()
	err = cipher.StartDecryptionWithKey(recipientId, privateKey, []byte{})
	assert.Nil(t, err)

	processDecryptionData, err := cipher.ProcessDecryption(encryptedData)
	assert.Nil(t, err)
	assert.NotNil(t, processDecryptionData)

	finishDecryptionData, err := cipher.FinishDecryption()
	assert.Nil(t, err)
	assert.NotNil(t, finishDecryptionData)

	decryptedData := append(processDecryptionData, finishDecryptionData...)
	assert.Equal(t, data, decryptedData)
}

func TestRecipientCipher_SetPaddingParams(t *testing.T) {
	paddingParams := NewPaddingParams()
	recipientCipher := NewRecipientCipher()
	recipientCipher.SetPaddingParams(paddingParams)
}
