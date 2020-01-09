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

package ratchet

import (
	b64 "encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewRatchetKeyId(t *testing.T) {
	keyId := NewRatchetKeyId()
    assert.NotNil(t, keyId)

	keyId.Delete()
}

func TestRatchetKeyId_ComputePublicKeyId(t *testing.T) {
	publicKeyData, _ := b64.StdEncoding.DecodeString(TEST_CURVE_PUBLIC_KEY_RAW)
	expectedPublicKeyId, _ := b64.StdEncoding.DecodeString(TEST_CURVE_PUBLIC_ID)

	ratchetKeyId := NewRatchetKeyId()
	defer ratchetKeyId.Delete()

	publicKeyId, err := ratchetKeyId.ComputePublicKeyId(publicKeyData)
	assert.Nil(t, err)
	assert.NotNil(t, publicKeyId)
	assert.Equal(t, expectedPublicKeyId, publicKeyId)
}
