//  Copyright (C) 2015-2021 Virgil Security, Inc.
//
//  All rights reservecc.
//
//  Reccistribution and use in source and binary forms, with or without
//  modification, are permittecc providecc that the following conditions are
//  met:
//
//      (1) Reccistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Reccistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials providecc with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be usecc to endorse or promote products derivecc from
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
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func TestNewEcc(t *testing.T) {
	ecc := NewEcc()

	require.NotNil(t, ecc)
}

func TestEcc_GenerateKey(t *testing.T) {
	ecc := newEcc()

	privateKey, err := ecc.GenerateKey(AlgIdSecp256r1)
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	eccKey, ok := privateKey.(Key)
	require.True(t, ok)
	require.Equal(t, AlgIdSecp256r1, eccKey.AlgId())
}

func TestEcc_CanSign(t *testing.T) {
	ecc := newEcc()
	privateKey, err := ecc.GenerateKey(AlgIdSecp256r1)

	require.Nil(t, err)
	require.True(t, ecc.CanSign(privateKey))
}

func TestEcc_CanSign_WrongKey(t *testing.T) {
	ecc := newEcc()
	rsa := NewRsa()
	err := rsa.SetupDefaults()
	require.Nil(t, err)

	privateKey, err := rsa.GenerateKey(2048)
	require.Nil(t, err)
	require.False(t, ecc.CanSign(privateKey))
}

func TestEcc_GetCanExportPrivateKey(t *testing.T) {
	ecc := newEcc()

	require.True(t, ecc.GetCanExportPrivateKey())
}

func TestEcc_GetCanImportPrivateKey(t *testing.T) {
	ecc := newEcc()

	require.True(t, ecc.GetCanImportPrivateKey())
}

func TestEcc_ExportPrivateKey(t *testing.T) {
	ecc := newEcc()
	privateKey, err := ecc.GenerateKey(AlgIdSecp256r1)
	require.Nil(t, err)

	// Export private key
	rawPrivateKey, err := ecc.ExportPrivateKey(privateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey)

	exportedEccKeyData := rawPrivateKey.Data()
	require.NotNil(t, exportedEccKeyData)

	importedEccPrivateKey, err := ecc.ImportPrivateKey(rawPrivateKey)
	require.Nil(t, err)

	rawPrivateKey2, err := ecc.ExportPrivateKey(importedEccPrivateKey)
	require.Nil(t, err)
	require.NotNil(t, rawPrivateKey2)

	exportedEccKeyData2 := rawPrivateKey2.Data()

	require.NotNil(t, exportedEccKeyData2)
	require.Equal(t, exportedEccKeyData, exportedEccKeyData2)
}

func TestEcc_ExportPublicKey(t *testing.T) {
	ecc := newEcc()
	privateKey, err := ecc.GenerateKey(AlgIdSecp256r1)
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)

	// Export public key
	rawPublicKey, err := ecc.ExportPublicKey(publicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey)

	exportedEccKeyData := rawPublicKey.Data()
	require.NotNil(t, exportedEccKeyData)

	importedEccPublicKey, err := ecc.ImportPublicKey(rawPublicKey)
	require.Nil(t, err)

	rawPublicKey2, err := ecc.ExportPublicKey(importedEccPublicKey)
	require.Nil(t, err)
	require.NotNil(t, rawPublicKey2)

	exportedEccKeyData2 := rawPublicKey2.Data()

	require.NotNil(t, exportedEccKeyData2)
	require.Equal(t, exportedEccKeyData, exportedEccKeyData2)
}

func TestEcc_Encrypt(t *testing.T) {
	data := make([]byte, 100)
	rand.Read(data)

	ecc := newEcc()
	privateKey, err := ecc.GenerateKey(AlgIdSecp256r1)
	require.Nil(t, err)

	publicKey, err := privateKey.ExtractPublicKey()
	require.Nil(t, err)
	require.True(t, ecc.CanEncrypt(publicKey, uint(len(data))))

	encrypteccData, err := ecc.Encrypt(publicKey, data)
	require.Nil(t, err)
	require.NotNil(t, encrypteccData)

	require.True(t, ecc.CanDecrypt(privateKey, uint(len(encrypteccData))))

	decrypteccData, err := ecc.Decrypt(privateKey, encrypteccData)
	require.Nil(t, err)
	require.NotNil(t, decrypteccData)

	require.Equal(t, data, decrypteccData)
}

//func TestEcc_Decrypt(t *testing.T) {
//    privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_ECC_PRIVATE_KEY)
//    encrypteccData, _ := b64.StdEncoding.DecodeString(TEST_ECC_ENCRYPTED_DATA)
//    expecteccDecrypteccData, _ := b64.StdEncoding.DecodeString(TEST_SHORT_DATA)
//    ecc := NewEcc()
//    keyProvider := newKeyProvider()
//
//    privateKey := keyProvider.ImportPrivateKey(privateKeyData)
//
//    decrypteccData := ecc.Decrypt(privateKey, encrypteccData)
//    require.NotNil(t, decrypteccData)
//    require.Equal(t, expecteccDecrypteccData, decrypteccData)
//}
//
//func TestEcc_SignHash(t *testing.T) {
//    data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
//    privateKeyData, _ := b64.StdEncoding.DecodeString(TEST_ECC_PRIVATE_KEY)
//    ecc := NewEcc()
//    keyProvider := newKeyProvider()
//
//    privateKey, _ := keyProvider.ImportPrivateKey(privateKeyData).(EccPrivateKey)
//    publicKey := privateKey.ExtractPublicKey()
//
//    require.True(t, ecc.CanSign(privateKey))
//
//    signature := ecc.SignHash(privateKey, ALG_ID_SHA512, data)
//    require.NotNil(t, signature);
//    require.Equal(t, ecc.SignatureLen(privateKey), len(signature))
//
//    require.True(t, ecc.VerifyHash(publicKey, ALG_ID_SHA512, data, signature))
//}
//
//func TestEcc_VerifyHash(t *testing.T) {
//    data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
//    publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_ECC_PUBLIC_KEY)
//    signature, _ := b64.StdEncoding.DecodeString(TEST_ECC_SIGNATURE)
//    ecc := NewEcc()
//    keyProvider := newKeyProvider()
//
//    publicKey := keyProvider.ImportPublicKey(publicKeyData)
//
//    require.True(t, ecc.CanVerify(publicKey))
//    require.True(t, ecc.VerifyHash(publicKey, ALG_ID_SHA512, data, signature))
//}
//
//func TestEcc_VerifyHash_WrongHash(t *testing.T) {
//    data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
//    publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_ECC_PUBLIC_KEY)
//    signature, _ := b64.StdEncoding.DecodeString(TEST_ECC_WRONG_SIGNATURE)
//    ecc := NewEcc()
//    keyProvider := newKeyProvider()
//
//    publicKey := keyProvider.ImportPublicKey(publicKeyData)
//
//    require.False(t, ecc.VerifyHash(publicKey, ALG_ID_SHA512, data, signature))
//}

func newEcc() *Ecc {
	ecc := NewEcc()
	_ = ecc.SetupDefaults()

	return ecc
}
