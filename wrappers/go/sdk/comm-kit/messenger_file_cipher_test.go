//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

package sdk_comm_kit

import (
	b64 "encoding/base64"
	"github.com/stretchr/testify/require"
	//	"reflect"
	"testing"
	foundation "virgil/foundation"
)

func TestProcessEncryption(t *testing.T) {
	publicKeyBytes, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PUBLIC_KEY)
	privateKeyBytes, _ := b64.StdEncoding.DecodeString(TEST_ED25519_PRIVATE_KEY)
	messageBytes, _ := b64.StdEncoding.DecodeString(TEST_MESSAGE)

	//  Prepare recipients
	keyProvider := foundation.NewKeyProvider()
	require.Nil(t, keyProvider.SetupDefaults())

	ownerPublicKey, err := keyProvider.ImportPublicKey(publicKeyBytes)
	require.Nil(t, err)

	ownerPrivateKey, err := keyProvider.ImportPrivateKey(privateKeyBytes)
	require.Nil(t, err)

	// Encrypt and sign
	fileCipher := NewMessengerFileCipher()
	require.Nil(t, fileCipher.SetupDefaults())

	fileKey, err := fileCipher.InitEncryption()
	require.NotNil(t, fileKey)
	require.Nil(t, err)

	headerBuf, err := fileCipher.StartEncryption()
	require.NotNil(t, headerBuf)
	require.Nil(t, err)

	dataBuf, err := fileCipher.ProcessEncryption(messageBytes)
	require.NotNil(t, dataBuf)
	require.Nil(t, err)

	finishBuf, signatureBuf, err := fileCipher.FinishEncryption(ownerPrivateKey)
	require.NotNil(t, finishBuf)
	require.NotNil(t, signatureBuf)
	require.Nil(t, err)

	// Decrypt
	err2 := fileCipher.StartDecryption(fileKey, signatureBuf)
	require.Nil(t, err2)

	headerBuffOut, err := fileCipher.ProcessDecryption(headerBuf)
	require.NotNil(t, headerBuffOut)
	require.Nil(t, err)

	dataBuffOut, err := fileCipher.ProcessDecryption(dataBuf)
	require.NotNil(t, dataBuffOut)
	require.Nil(t, err)

	finishBufOut, err := fileCipher.ProcessDecryption(finishBuf)
	require.NotNil(t, finishBufOut)
	require.Nil(t, err)

	finalBufOut, err := fileCipher.FinishDecryption(ownerPublicKey)
	require.NotNil(t, finalBufOut)
	require.Nil(t, err)

	//TODO
	//bufOut := append(headerBuffOut, dataBuffOut, finishBufOut, finalBufOut)

	//require.Equal(t, messageBytes, bufOut)
}
