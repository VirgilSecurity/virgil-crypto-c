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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewKeyProvider(t *testing.T) {
	keyProvider := NewKeyProvider()

	require.NotNil(t, keyProvider)
}

func TestKeyProvider_ImportPrivateKey_EmptyData(t *testing.T) {
	keyProvider := newKeyProvider()

	importedKey, err := keyProvider.ImportPrivateKey([]byte{})
	require.NotNil(t, err)
	require.Nil(t, importedKey)
}

func TestKeyProvider_ImportPrivateKey_WrongData(t *testing.T) {
	wrongKeyData, _ := b64.StdEncoding.DecodeString(TEST_KEY_PROVIDER_WRONG_KEY)
	keyProvider := newKeyProvider()

	importedKey, err := keyProvider.ImportPrivateKey(wrongKeyData)
	require.NotNil(t, err)
	require.Nil(t, importedKey)
}

func TestKeyProvider_ImportPrivateKey(t *testing.T) {
	keyData, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PRIVATE_KEY)
	keyProvider := newKeyProvider()

	privateKey, err := keyProvider.ImportPrivateKey(keyData)
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	iKey, _ := privateKey.(Key)
	require.True(t, iKey.IsValid())

	exportedPrivateKeyData, err := keyProvider.ExportPrivateKey(privateKey)
	require.Nil(t, err)

	pk, err := keyProvider.ImportPrivateKey(exportedPrivateKeyData)
	require.Nil(t, err)

	importedPrivateKey := pk.(Key)
	require.True(t, importedPrivateKey.IsValid())
}
