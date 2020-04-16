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

package phe

import (
	"github.com/stretchr/testify/require"
	"testing"
	"virgil/foundation"
)

func TestNewPheCipher(t *testing.T) {
	cipher := NewPheCipher()
	require.NotNil(t, cipher)

	cipher.Delete()
}

func TestNewPheCipherWithCtx(t *testing.T) {
	cipher := NewPheCipher()
	defer cipher.Delete()

	newCipher := newPheCipherWithCtx(cipher.cCtx)
	require.NotNil(t, newCipher)
	require.Equal(t, cipher.cCtx, newCipher.cCtx)
}

func TestFullFlowShouldSucceed(t *testing.T) {
	plainText := []byte("plain text")
	accountKey := []byte("Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC") // 32 bytes string
	require.Equal(t, 32, len(accountKey))

	cipher := NewPheCipher()
	defer cipher.Delete()
	err := cipher.SetupDefaults()
	require.Nil(t, err)

	encryptedData, err := cipher.Encrypt(plainText, accountKey)
	require.Nil(t, err)

	decryptedData, err := cipher.Decrypt(encryptedData, accountKey)
	require.Nil(t, err)

	require.Equal(t, plainText, decryptedData)
}

func TestFullFlowShouldSucceed_customRandom(t *testing.T) {
	plainText := []byte("plain text")
	accountKey := []byte("Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC") // 32 bytes string
	require.Equal(t, 32, len(accountKey))

	random := foundation.NewCtrDrbg()
	err := random.SetupDefaults()
	require.Nil(t, err)

	cipher := NewPheCipher()
	defer cipher.Delete()

	cipher.SetRandom(random)
	//err := cipher.SetupDefaults()
	//require.Nil(t, err)

	encryptedData, err := cipher.Encrypt(plainText, accountKey)
	require.Nil(t, err)

	decryptedData, err := cipher.Decrypt(encryptedData, accountKey)
	require.Nil(t, err)

	require.Equal(t, plainText, decryptedData)
}

func TestFullFlowWrongKeyShouldFail(t *testing.T) {
	plainText := []byte("plain text")
	accountKey := []byte("Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC")
	wrongAccountKey := []byte("Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjD")

	cipher := NewPheCipher()
	defer cipher.Delete()
	err := cipher.SetupDefaults()
	require.Nil(t, err)

	encryptedData, err := cipher.Encrypt(plainText, accountKey)
	require.Nil(t, err)

	decryptedData, err := cipher.Decrypt(encryptedData, wrongAccountKey)
	require.Nil(t, decryptedData)
	require.NotNil(t, err)
	//FIXME require.Equal(t, PHE_ERROR_ERROR_AES_FAILED, err.(PheError).Code)
}
