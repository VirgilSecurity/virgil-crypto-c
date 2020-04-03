//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRsa(t *testing.T) {
	rsa := NewRsa()

	require.NotNil(t, rsa)
}

func TestRsa_GenerateKey(t *testing.T) {
	rsa := newRsa()
	bitlen := TEST_RSA_KEY_BIT_LEN

	privateKey, err := rsa.GenerateKey(bitlen)
	require.Nil(t, err)

	require.NotNil(t, privateKey)

	rsaKey, ok := privateKey.(Key)
	require.True(t, ok)
	require.Equal(t, AlgIdRsa, rsaKey.AlgId())
	require.Equal(t, bitlen, rsaKey.Bitlen())
}

func TestRsa_CanSign(t *testing.T) {
	bitlen := TEST_RSA_KEY_BIT_LEN
	rsa := newRsa()
	privateKey, err := rsa.GenerateKey(bitlen)
	require.Nil(t, err)

	require.True(t, rsa.CanSign(privateKey))
}

func TestRsa_CanSign_WrongKey(t *testing.T) {
	rsa := newRsa()
	ed := NewEd25519()
	err := ed.SetupDefaults()
	require.Nil(t, err)

	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)

	require.False(t, rsa.CanSign(privateKey))
}

func TestRsa_GetCanExportPrivateKey(t *testing.T) {
	rsa := newRsa()

	require.True(t, rsa.GetCanExportPrivateKey())
}

func TestRsa_GetCanImportPrivateKey(t *testing.T) {
	rsa := newRsa()

	require.True(t, rsa.GetCanImportPrivateKey())
}

func TestRsa_ExportPrivateKey(t *testing.T) {
	bitlen := TEST_RSA_KEY_BIT_LEN
	rsa := newRsa()

	privateKey, err := rsa.GenerateKey(bitlen)
	require.Nil(t, err)

	// Export private key
	rawPrivateKey, err := rsa.ExportPrivateKey(privateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey)

	exportedKeyData := rawPrivateKey.Data()
	require.NotNil(t, exportedKeyData)

	importedPrivateKey, err := rsa.ImportPrivateKey(rawPrivateKey)
	require.Nil(t, err)

	rawPrivateKey2, err := rsa.ExportPrivateKey(importedPrivateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey2)

	exportedKeyData2 := rawPrivateKey2.Data()

	require.NotNil(t, exportedKeyData2)
	require.Equal(t, exportedKeyData, exportedKeyData2)
}

func TestRsa_ExportPublicKey(t *testing.T) {
	bitlen := TEST_RSA_KEY_BIT_LEN
	rsa := newRsa()

	privateKey, err := rsa.GenerateKey(bitlen)
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	// Export public key
	rawPublicKey, err := rsa.ExportPublicKey(publicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey)

	exportedKeyData := rawPublicKey.Data()
	require.NotNil(t, exportedKeyData)

	importedPublicKey, err := rsa.ImportPublicKey(rawPublicKey)
	require.Nil(t, err)

	rawPublicKey2, err := rsa.ExportPublicKey(importedPublicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey2)

	exportedKeyData2 := rawPublicKey2.Data()

	require.NotNil(t, exportedKeyData2)
	require.Equal(t, exportedKeyData, exportedKeyData2)
}

func TestRsa_Encrypt(t *testing.T) {
	data := make([]byte, 100)
	rand.Read(data)

	bitlen := TEST_RSA_KEY_BIT_LEN
	rsa := newRsa()

	privateKey, err := rsa.GenerateKey(bitlen)
	require.Nil(t, err)
	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	require.True(t, rsa.CanEncrypt(publicKey, uint(len(data))))

	encryptedData, err := rsa.Encrypt(publicKey, data)
	require.Nil(t, err)
	require.NotNil(t, encryptedData)

	require.True(t, rsa.CanDecrypt(privateKey, uint(len(encryptedData))))

	decryptedData, err := rsa.Decrypt(privateKey, encryptedData)
	require.Nil(t, err)
	require.NotNil(t, decryptedData)

	require.Equal(t, data, decryptedData)
}

func TestRsa_Decrypt(t *testing.T) {
	privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_RSA_PRIVATE_KEY)
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_RSA_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_SHORT_DATA)
	rsa := newRsa()
	keyProvider := newKeyProvider()

	privateKey, err := keyProvider.ImportPrivateKey(privateKeyData)
	require.Nil(t, err)

	decryptedData, err := rsa.Decrypt(privateKey, encryptedData)
	require.Nil(t, err)
	require.NotNil(t, decryptedData)
	require.Equal(t, expectedDecryptedData, decryptedData)
}

func TestRsa_SignHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_RSA_PRIVATE_KEY)
	rsa := newRsa()
	keyProvider := newKeyProvider()

	privateKey, err := keyProvider.ImportPrivateKey(privateKeyData)
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	require.True(t, rsa.CanSign(privateKey))

	signature, err := rsa.SignHash(privateKey, AlgIdSha512, data)
	require.Nil(t, err)

	require.NotNil(t, signature)
	require.Equal(t, rsa.SignatureLen(privateKey), uint(len(signature)))

	require.True(t, rsa.VerifyHash(publicKey, AlgIdSha512, data, signature))
}

func TestRsa_VerifyHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_RSA_PUBLIC_KEY)
	signature, _ := b64.StdEncoding.DecodeString(TEST_RSA_SIGNATURE)
	rsa := newRsa()
	keyProvider := newKeyProvider()

	publicKey, err := keyProvider.ImportPublicKey(publicKeyData)
	require.Nil(t, err)
	require.True(t, rsa.CanVerify(publicKey))
	require.True(t, rsa.VerifyHash(publicKey, AlgIdSha512, data, signature))
}

func TestRsa_VerifyHash_WrongHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_RSA_PUBLIC_KEY)
	signature, _ := b64.StdEncoding.DecodeString(TEST_RSA_WRONG_SIGNATURE)
	rsa := newRsa()
	keyProvider := newKeyProvider()

	publicKey, err := keyProvider.ImportPublicKey(publicKeyData)
	require.Nil(t, err)
	require.False(t, rsa.VerifyHash(publicKey, AlgIdSha512, data, signature))
}

func newRsa() *Rsa {
	rsa := NewRsa()
	_ = rsa.SetupDefaults()

	return rsa
}

func newKeyProvider() *KeyProvider {
	keyProvider := NewKeyProvider()
	_ = keyProvider.SetupDefaults()

	return keyProvider
}
