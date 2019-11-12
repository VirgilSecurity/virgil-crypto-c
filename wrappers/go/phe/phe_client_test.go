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

package phe

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPheClient(t *testing.T) {
	client := NewPheClient()
    assert.NotNil(t, client)

	client.Delete()
}

func TestFullFlowRandomCorrectPwdShouldSucceed(t *testing.T) {
	password := []byte("password")

	client := newPheClient()
	defer client.Delete()

	server := newPheServer()
	defer server.Delete()

	serverPrivateKey, serverPublicKey, err := server.GenerateServerKeyPair()
	assert.Nil(t, err)
	assert.Equal(t, 32, len(serverPrivateKey))
	assert.Equal(t, 65, len(serverPublicKey))

	clientPrivateKey, err := client.GenerateClientPrivateKey()
	assert.Nil(t, err)
	assert.NotNil(t, clientPrivateKey)

	err = client.SetKeys(clientPrivateKey, serverPublicKey)
	assert.Nil(t, err)

	serverEnrollment, err := server.GetEnrollment(serverPrivateKey, serverPublicKey)
	assert.Nil(t, err)
	assert.NotNil(t, serverEnrollment)
	assert.True(t, len(serverEnrollment) > 0)

	clientEnrollmentRecord, clientAccountKey, err := client.EnrollAccount(serverEnrollment, password)
	assert.Nil(t, err);
	assert.NotNil(t, clientEnrollmentRecord)
	assert.NotNil(t, clientAccountKey)
	assert.Equal(t, 32, len(clientAccountKey))

	clientCreateVerifyPasswordRequest, err := client.CreateVerifyPasswordRequest(password, clientEnrollmentRecord)
	assert.Nil(t, err)
	assert.NotNil(t, clientCreateVerifyPasswordRequest)
	assert.True(t, len(clientCreateVerifyPasswordRequest) > 0)

	serverVerifyPassword, err := server.VerifyPassword(serverPrivateKey, serverPublicKey, clientCreateVerifyPasswordRequest)
	assert.Nil(t, err)
	assert.NotNil(t, serverVerifyPassword)

	clientCheckResponseAndDecrypt, err := client.CheckResponseAndDecrypt(password, clientEnrollmentRecord, serverVerifyPassword)
	assert.Nil(t, err)
	assert.NotNil(t, clientCheckResponseAndDecrypt)
	assert.Equal(t, 32, len(clientCheckResponseAndDecrypt))
	assert.Equal(t, clientAccountKey, clientCheckResponseAndDecrypt)
}

func TestRotationRandomRotationServerPublicKeysMatch(t *testing.T) {
	client := newPheClient()
	defer client.Delete()

	server := newPheServer()
	defer server.Delete()

	serverPrivateKey, serverPublicKey, err := server.GenerateServerKeyPair()
	assert.Nil(t, err)
	assert.NotNil(t, serverPrivateKey)
	assert.NotNil(t, serverPublicKey)

	serverRotatedPrivateKey, serverRotatedPublicKey, serverUpdateToken, err := server.RotateKeys(serverPrivateKey)
	assert.Nil(t, err)

	assert.NotNil(t, serverRotatedPrivateKey)
	assert.Equal(t,32, len(serverRotatedPrivateKey))

	assert.NotNil(t, serverRotatedPublicKey)
	assert.Equal(t, 65, len(serverRotatedPublicKey))

	assert.NotNil(t, serverUpdateToken)
	assert.True(t, len(serverUpdateToken) > 0)

	clientPrivateKey, err := client.GenerateClientPrivateKey()
	assert.Nil(t, err)
	assert.NotNil(t, clientPrivateKey)
	assert.Equal(t, 32, len(clientPrivateKey))

	err = client.SetKeys(clientPrivateKey, serverRotatedPublicKey)
	assert.Nil(t, err)

	clientNewPrivateKey, serverNewPublicKey, err := client.RotateKeys(serverUpdateToken)
	assert.Nil(t, err)

	assert.NotNil(t, clientNewPrivateKey)
	assert.Equal(t, 32, len(clientNewPrivateKey))

	assert.NotNil(t, serverNewPublicKey)
	assert.Equal(t,65, len(serverNewPublicKey))

	assert.Equal(t, len(serverPublicKey), len(serverNewPublicKey))
	assert.Equal(t, len(clientPrivateKey), len(clientNewPrivateKey))
}

func newPheClient() *PheClient {
	client := NewPheClient()
	_ = client.SetupDefaults()

	return client
}