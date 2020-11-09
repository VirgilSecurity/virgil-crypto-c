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

func TestBinaryFromHex(t *testing.T) {
	hex := TEST_BINARY_HEX
	expectedData, _ := b64.StdEncoding.DecodeString(TEST_DATA)

	data, err := BinaryFromHex(hex)

	require.Nil(t, err)
	require.NotNil(t, data)
	require.Equal(t, expectedData, data)
}

func TestBinaryFromHexLen(t *testing.T) {
	data := TEST_BINARY_HEX
	expectedDataLen := TEST_BINARY_DATA_LEN

	dataLen := BinaryFromHexLen(uint(len(data)))
	require.Equal(t, expectedDataLen, int(dataLen))
}

func TestBinaryToHex(t *testing.T) {
	data, _ := b64.StdEncoding.DecodeString(TEST_DATA)
	expectedHex := TEST_BINARY_HEX

	hex := BinaryToHex(data)

	require.NotNil(t, hex)
	require.Equal(t, expectedHex, hex)
}

func TestBinaryToHexLen(t *testing.T) {
	data := TEST_DATA
	expectedHexLen := TEST_BINARY_HEX_LEN

	hexLen := BinaryToHexLen(uint(len(data)))
	require.Equal(t, expectedHexLen, int(hexLen))
}
