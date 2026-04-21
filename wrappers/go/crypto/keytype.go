/*
 * Copyright (C) 2015-2026 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package crypto

import (
	"virgil/foundation"
)

type KeyType int

const (
	DefaultKeyType KeyType = iota
	Rsa2048
	Rsa3072
	Rsa4096
	Rsa8192
	P256r1
	Curve25519
	Ed25519
	Curve25519Ed25519
	Curve25519Round5Ed25519Falcon
	Curve25519Round5
	Curve25519Curve25519
)

type keyGen interface {
	GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error)
}

var keyTypeMap = map[KeyType]keyGen{
	DefaultKeyType: keyType(foundation.AlgIdEd25519),
	Rsa2048:        rsaKeyType(2048),
	Rsa3072:        rsaKeyType(3072),
	Rsa4096:        rsaKeyType(4096),
	Rsa8192:        rsaKeyType(8192),
	P256r1:         keyType(foundation.AlgIdSecp256r1),
	Curve25519:     keyType(foundation.AlgIdCurve25519),
	Ed25519:        keyType(foundation.AlgIdEd25519),
	Curve25519Ed25519: &compoundHybridKeyType{
		cipherFirstKeyAlgId:  foundation.AlgIdCurve25519,
		cipherSecondKeyAlgId: foundation.AlgIdNone,
		signerFirstKeyAlgId:  foundation.AlgIdEd25519,
		signerSecondKeyAlgId: foundation.AlgIdNone,
	},
	Curve25519Round5Ed25519Falcon: &compoundHybridKeyType{
		cipherFirstKeyAlgId:  foundation.AlgIdCurve25519,
		cipherSecondKeyAlgId: foundation.AlgIdRound5Nd1cca5d,
		signerFirstKeyAlgId:  foundation.AlgIdEd25519,
		signerSecondKeyAlgId: foundation.AlgIdFalcon,
	},
	Curve25519Round5: &hybridKeyType{
		firstKeyAlgId:  foundation.AlgIdCurve25519,
		secondKeyAlgId: foundation.AlgIdRound5Nd1cca5d,
	},
	Curve25519Curve25519: &hybridKeyType{
		firstKeyAlgId:  foundation.AlgIdCurve25519,
		secondKeyAlgId: foundation.AlgIdCurve25519,
	},
}

type keyType foundation.AlgId

func (t keyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	return kp.GeneratePrivateKey(foundation.AlgId(t))
}

type rsaKeyType int

func (t rsaKeyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	kp.SetRsaParams(uint(t))
	return kp.GeneratePrivateKey(foundation.AlgIdRsa)
}

type compoundHybridKeyType struct {
	cipherFirstKeyAlgId  foundation.AlgId
	cipherSecondKeyAlgId foundation.AlgId
	signerFirstKeyAlgId  foundation.AlgId
	signerSecondKeyAlgId foundation.AlgId
}

func (t *compoundHybridKeyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	return kp.GenerateCompoundHybridPrivateKey(
		t.cipherFirstKeyAlgId,
		t.cipherSecondKeyAlgId,
		t.signerFirstKeyAlgId,
		t.signerSecondKeyAlgId,
	)
}

type hybridKeyType struct {
	firstKeyAlgId  foundation.AlgId
	secondKeyAlgId foundation.AlgId
}

func (t *hybridKeyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	return kp.GenerateHybridPrivateKey(
		t.firstKeyAlgId,
		t.secondKeyAlgId,
	)
}

func getKeyType(obj deleter) (KeyType, error) {

	key, ok := obj.(foundation.Key)
	if !ok {
		return DefaultKeyType, ErrUnsupportedKeyType
	}

	algInfo, err := key.AlgInfo()
	if err != nil {
		return DefaultKeyType, err
	}
	info := foundation.NewKeyInfoWithAlgInfo(algInfo)
	if info.IsCompound() {
		if info.CompoundHybridCipherFirstKeyAlgId() == foundation.AlgIdCurve25519 &&
			info.CompoundHybridCipherSecondKeyAlgId() == foundation.AlgIdRound5Nd1cca5d &&
			info.CompoundHybridSignerFirstKeyAlgId() == foundation.AlgIdEd25519 &&
			info.CompoundHybridSignerSecondKeyAlgId() == foundation.AlgIdFalcon {
			return Curve25519Round5Ed25519Falcon, nil
		} else if info.CompoundCipherAlgId() == foundation.AlgIdCurve25519 &&
			info.CompoundSignerAlgId() == foundation.AlgIdEd25519 {
			return Curve25519Ed25519, nil
		} else {
			return DefaultKeyType, ErrUnsupportedKeyType
		}
	}

	if info.IsHybrid() {
		if info.HybridFirstKeyAlgId() == foundation.AlgIdCurve25519 &&
			info.HybridSecondKeyAlgId() == foundation.AlgIdRound5Nd1cca5d {
			return Curve25519Round5, nil
		}
		if info.HybridFirstKeyAlgId() == foundation.AlgIdCurve25519 &&
			info.HybridSecondKeyAlgId() == foundation.AlgIdCurve25519 {
			return Curve25519Curve25519, nil
		}

		return DefaultKeyType, ErrUnsupportedKeyType
	}

	if algInfo.AlgId() == foundation.AlgIdRsa {
		switch key.Bitlen() {
		case 2048:
			return Rsa2048, nil
		case 3072:
			return Rsa3072, nil
		case 4096:
			return Rsa4096, nil
		case 8192:
			return Rsa8192, nil
		default:
			return DefaultKeyType, ErrUnsupportedKeyType
		}
	}

	switch algInfo.AlgId() {
	case foundation.AlgIdCurve25519:
		return Curve25519, nil
	case foundation.AlgIdEd25519:
		return Ed25519, nil
	case foundation.AlgIdSecp256r1:
		return P256r1, nil
	default:
		return DefaultKeyType, ErrUnsupportedKeyType
	}
}
