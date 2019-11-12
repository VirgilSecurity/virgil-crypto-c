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

package pythia

import (
	b64 "encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPythiaConfigure(t *testing.T) {
	err := PythiaConfigure()
    assert.Nil(t, err)
}

func TestPythiaBlind(t *testing.T) {
	err := PythiaConfigure()
	assert.Nil(t, err)

	password := []byte(TEST_PASSWORD)

	blindedPassword, blindingSecret, err := PythiaBlind(password)
	assert.Nil(t, err)
	assert.NotNil(t, blindedPassword)
	assert.NotNil(t, blindingSecret)
}

func TestPythiaBlindEvalDeblind(t *testing.T) {
	transformationKeyId := []byte(TEST_W)
	tweak := []byte(TEST_T)
	pythiaSecret := []byte(TEST_MSK)
	pythiaScopeSecret := []byte(TEST_SSK)
	password := []byte(TEST_PASSWORD)
	expectedDeblindedPassword, _ := b64.StdEncoding.DecodeString(TEST_DEBLINDED_PASSWORD)

	err := PythiaConfigure()
	assert.Nil(t, err)

	blindedPassword, blindingSecret, err := PythiaBlind(password)
	assert.Nil(t, err)

	transformationPrivateKey, transformationPublicKey, err := PythiaComputeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
	assert.Nil(t, err)
	assert.NotNil(t, transformationPrivateKey)
	assert.NotNil(t, transformationPublicKey)

	transformedPassword, transformedTweak, err := PythiaTransform(blindedPassword, tweak, transformationPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, transformedPassword)
	assert.NotNil(t, transformedTweak)

	deblindedPassword, err := PythiaDeblind(transformedPassword, blindingSecret)
	assert.Nil(t, err)

	assert.Equal(t, expectedDeblindedPassword, deblindedPassword)
}

func TestPythiaBlindEvalProveVerify(t *testing.T) {
	transformationKeyId := []byte(TEST_W)
	tweak := []byte(TEST_T)
	pythiaSecret := []byte(TEST_MSK)
	pythiaScopeSecret := []byte(TEST_SSK)
	password := []byte(TEST_PASSWORD)

	err := PythiaConfigure()
	assert.Nil(t, err)

	blindedPassword, blindingSecret, err := PythiaBlind(password)
	assert.Nil(t, err)
	assert.NotNil(t, blindedPassword)
	assert.NotNil(t, blindingSecret)

	transformationPrivateKey, transformationPublicKey, err := PythiaComputeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
	assert.Nil(t, err)
	assert.NotNil(t, transformationPrivateKey)
	assert.NotNil(t, transformationPublicKey)

	transformedPassword, transformedTweak, err := PythiaTransform(blindedPassword, tweak, transformationPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, transformedPassword)
	assert.NotNil(t, transformedTweak)

	proofValueC, proofValueU, err := PythiaProve(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey,
		transformationPublicKey)
	assert.Nil(t, err)
	assert.NotNil(t, proofValueC)
	assert.NotNil(t, proofValueU)

	verified, err := PythiaVerify(transformedPassword, blindedPassword, tweak, transformationPublicKey,
		proofValueC, proofValueU)
	assert.Nil(t, err)
	assert.True(t, verified)
}
