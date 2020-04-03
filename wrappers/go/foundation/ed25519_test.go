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

func TestNewEd25519(t *testing.T) {
	ed := NewEd25519()

	require.NotNil(t, ed)
}

func TestEd25519_GenerateKey(t *testing.T) {
	ed := newEd25519()

	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	edKey, ok := privateKey.(Key)
	require.True(t, ok)
	require.Equal(t, AlgIdEd25519, edKey.AlgId())
}

func TestEd25519_CanSign(t *testing.T) {
	ed := newEd25519()
	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)
	require.True(t, ed.CanSign(privateKey))
}

func TestEd25519_CanSign_WrongKey(t *testing.T) {
	ed := newEd25519()
	rsa := NewRsa()
	err := rsa.SetupDefaults()
	require.Nil(t, err)

	privateKey, err := rsa.GenerateKey(2048)
	require.Nil(t, err)
	require.False(t, ed.CanSign(privateKey))
}

func TestEd25519_GetCanExportPrivateKey(t *testing.T) {
	ed := newEd25519()

	require.True(t, ed.GetCanExportPrivateKey())
}

func TestEd25519_GetCanImportPrivateKey(t *testing.T) {
	ed := newEd25519()

	require.True(t, ed.GetCanImportPrivateKey())
}

func TestEd25519_ExportPrivateKey(t *testing.T) {
	ed := newEd25519()
	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)

	// Export private key
	rawPrivateKey, err := ed.ExportPrivateKey(privateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey)

	exportedKeyData := rawPrivateKey.Data()
	require.NotNil(t, exportedKeyData)

	importedPrivateKey, err := ed.ImportPrivateKey(rawPrivateKey)
	require.Nil(t, err)

	rawPrivateKey2, err := ed.ExportPrivateKey(importedPrivateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey2)

	exportedKeyData2 := rawPrivateKey2.Data()

	require.NotNil(t, exportedKeyData2)
	require.Equal(t, exportedKeyData, exportedKeyData2)
}

func TestEd25519_ExportPublicKey(t *testing.T) {
	ed := newEd25519()
	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	// Export public key
	rawPublicKey, err := ed.ExportPublicKey(publicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey)

	exportedKeyData := rawPublicKey.Data()
	require.NotNil(t, exportedKeyData)

	importedPublicKey, err := ed.ImportPublicKey(rawPublicKey)
	require.Nil(t, err)

	rawPublicKey2, err := ed.ExportPublicKey(importedPublicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey2)

	exportedKeyData2 := rawPublicKey2.Data()

	require.NotNil(t, exportedKeyData2)
	require.Equal(t, exportedKeyData, exportedKeyData2)
}

func TestEd25519_Encrypt(t *testing.T) {
	data := make([]byte, 100)
	rand.Read(data)

	ed := newEd25519()
	privateKey, err := ed.GenerateKey()
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	require.True(t, ed.CanEncrypt(publicKey, uint(len(data))))

	encryptedData, err := ed.Encrypt(publicKey, data)
	require.Nil(t, err)
	require.NotNil(t, encryptedData)

	require.True(t, ed.CanDecrypt(privateKey, uint(len(encryptedData))))

	decryptedData, err := ed.Decrypt(privateKey, encryptedData)
	require.Nil(t, err)
	require.NotNil(t, decryptedData)

	require.Equal(t, data, decryptedData)
}

func TestEd25519_Decrypt(t *testing.T) {
	privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PRIVATE_KEY)
	encryptedData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_ENCRYPTED_DATA)
	expectedDecryptedData, _ := b64.StdEncoding.DecodeString(TEST_SHORT_DATA)
	ed := newEd25519()
	keyProvider := newKeyProvider()

	privateKey, err := keyProvider.ImportPrivateKey(privateKeyData)
	require.Nil(t, err)

	decryptedData, err := ed.Decrypt(privateKey, encryptedData)
	require.Nil(t, err)
	require.NotNil(t, decryptedData)
	require.Equal(t, expectedDecryptedData, decryptedData)
}

func TestEd25519_SignHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PRIVATE_KEY)
	ed := newEd25519()
	keyProvider := newKeyProvider()

	privateKey, err := keyProvider.ImportPrivateKey(privateKeyData)
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)
	require.True(t, ed.CanSign(privateKey))

	signature, err := ed.SignHash(privateKey, AlgIdSha512, data)
	require.Nil(t, err)
	require.NotNil(t, signature)
	require.Equal(t, ed.SignatureLen(privateKey), uint(len(signature)))

	require.True(t, ed.VerifyHash(publicKey, AlgIdSha512, data, signature))
}

func TestEd25519_VerifyHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PUBLIC_KEY)
	signature, _ := b64.StdEncoding.DecodeString(TEST_ED25519_SIGNATURE)
	ed := newEd25519()
	keyProvider := newKeyProvider()

	publicKey, err := keyProvider.ImportPublicKey(publicKeyData)
	require.Nil(t, err)
	require.True(t, ed.CanVerify(publicKey))
	require.True(t, ed.VerifyHash(publicKey, AlgIdSha512, data, signature))
}

func TestEd25519_VerifyHash_WrongHash(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PUBLIC_KEY)
	signature, _ := b64.StdEncoding.DecodeString(TEST_ED25519_WRONG_SIGNATURE)
	ed := newEd25519()
	keyProvider := newKeyProvider()

	publicKey, err := keyProvider.ImportPublicKey(publicKeyData)
	require.Nil(t, err)
	require.False(t, ed.VerifyHash(publicKey, AlgIdSha512, data, signature))

}
func newEd25519() *Ed25519 {
	ed := NewEd25519()
	_ = ed.SetupDefaults()

	return ed
}
