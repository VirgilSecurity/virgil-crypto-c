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
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	expectedEncodedData := []byte(TEST_DATA)

	encodedData := Base64Encode(data)
	assert.NotNil(t, encodedData)
	assert.True(t, reflect.DeepEqual(expectedEncodedData, encodedData))
}

func TestBase64EncodedLen(t *testing.T) {
	assert.Equal(t, uint(0), Base64EncodedLen(0))
	assert.Equal(t, uint(5), Base64EncodedLen(1))
	assert.Equal(t, uint(9), Base64EncodedLen(4))
}

func TestBase64Decode(t *testing.T) {
	encodedData := []byte(TEST_DATA)
	expectedDecodedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)

	decodedData, err := Base64Decode(encodedData)

	assert.Nil(t, err)
	assert.NotNil(t, decodedData)
	assert.Equal(t, expectedDecodedData, decodedData)
}

func TestBase64DecodedLen(t *testing.T) {
	assert.Equal(t, uint(0), Base64DecodedLen(0))
	assert.Equal(t, uint(4), Base64DecodedLen(1))
}
