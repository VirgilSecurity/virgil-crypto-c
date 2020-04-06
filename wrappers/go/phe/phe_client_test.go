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
)

func TestNewPheClient(t *testing.T) {
	client := NewPheClient()
    require.NotNil(t, client)

	client.Delete()
}

func TestFullFlowRandomCorrectPwdShouldSucceed(t *testing.T) {
	password := []byte("password")

	client := newPheClient()
	defer client.Delete()

	server := newPheServer()
	defer server.Delete()

	serverPrivateKey, serverPublicKey, err := server.GenerateServerKeyPair()
	require.Nil(t, err)
	require.Equal(t, 32, len(serverPrivateKey))
	require.Equal(t, 65, len(serverPublicKey))

	clientPrivateKey, err := client.GenerateClientPrivateKey()
	require.Nil(t, err)
	require.NotNil(t, clientPrivateKey)

	err = client.SetKeys(clientPrivateKey, serverPublicKey)
	require.Nil(t, err)

	serverEnrollment, err := server.GetEnrollment(serverPrivateKey, serverPublicKey)
	require.Nil(t, err)
	require.NotNil(t, serverEnrollment)
	require.True(t, len(serverEnrollment) > 0)

	clientEnrollmentRecord, clientAccountKey, err := client.EnrollAccount(serverEnrollment, password)
	require.Nil(t, err);
	require.NotNil(t, clientEnrollmentRecord)
	require.NotNil(t, clientAccountKey)
	require.Equal(t, 32, len(clientAccountKey))

	clientCreateVerifyPasswordRequest, err := client.CreateVerifyPasswordRequest(password, clientEnrollmentRecord)
	require.Nil(t, err)
	require.NotNil(t, clientCreateVerifyPasswordRequest)
	require.True(t, len(clientCreateVerifyPasswordRequest) > 0)

	serverVerifyPassword, err := server.VerifyPassword(serverPrivateKey, serverPublicKey, clientCreateVerifyPasswordRequest)
	require.Nil(t, err)
	require.NotNil(t, serverVerifyPassword)

	clientCheckResponseAndDecrypt, err := client.CheckResponseAndDecrypt(password, clientEnrollmentRecord, serverVerifyPassword)
	require.Nil(t, err)
	require.NotNil(t, clientCheckResponseAndDecrypt)
	require.Equal(t, 32, len(clientCheckResponseAndDecrypt))
	require.Equal(t, clientAccountKey, clientCheckResponseAndDecrypt)
}

func TestRotationRandomRotationServerPublicKeysMatch(t *testing.T) {
	client := newPheClient()
	defer client.Delete()

	server := newPheServer()
	defer server.Delete()

	serverPrivateKey, serverPublicKey, err := server.GenerateServerKeyPair()
	require.Nil(t, err)
	require.NotNil(t, serverPrivateKey)
	require.NotNil(t, serverPublicKey)

	serverRotatedPrivateKey, serverRotatedPublicKey, serverUpdateToken, err := server.RotateKeys(serverPrivateKey)
	require.Nil(t, err)

	require.NotNil(t, serverRotatedPrivateKey)
	require.Equal(t,32, len(serverRotatedPrivateKey))

	require.NotNil(t, serverRotatedPublicKey)
	require.Equal(t, 65, len(serverRotatedPublicKey))

	require.NotNil(t, serverUpdateToken)
	require.True(t, len(serverUpdateToken) > 0)

	clientPrivateKey, err := client.GenerateClientPrivateKey()
	require.Nil(t, err)
	require.NotNil(t, clientPrivateKey)
	require.Equal(t, 32, len(clientPrivateKey))

	err = client.SetKeys(clientPrivateKey, serverRotatedPublicKey)
	require.Nil(t, err)

	clientNewPrivateKey, serverNewPublicKey, err := client.RotateKeys(serverUpdateToken)
	require.Nil(t, err)

	require.NotNil(t, clientNewPrivateKey)
	require.Equal(t, 32, len(clientNewPrivateKey))

	require.NotNil(t, serverNewPublicKey)
	require.Equal(t,65, len(serverNewPublicKey))

	require.Equal(t, len(serverPublicKey), len(serverNewPublicKey))
	require.Equal(t, len(clientPrivateKey), len(clientNewPrivateKey))
}

func newPheClient() *PheClient {
	client := NewPheClient()
	_ = client.SetupDefaults()

	return client
}