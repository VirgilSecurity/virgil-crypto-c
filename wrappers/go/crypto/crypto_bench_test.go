/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"virgil/crypto"
)

func BenchmarkSign(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerKeypair, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = vcrypto.Sign(data, signerKeypair)
		if err != nil {
			b.Fatalf("Sing return error: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	sign, err := vcrypto.Sign(data, signerSk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = vcrypto.VerifySignature(data, sign, signerPk); err != nil {
			b.Fatalf("Sing return error: %v", err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vcrypto.Encrypt(data, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptHybridCurveCurve(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypairForType(crypto.Curve25519Curve25519)
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vcrypto.Encrypt(data, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkEncryptHybridCurveRound5(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypairForType(crypto.Curve25519Round5)
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vcrypto.Encrypt(data, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	keypair, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)

	data, err = vcrypto.Encrypt(data, keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = vcrypto.Decrypt(data, keypair); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptHybridCurveCurve(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	keypair, err := vcrypto.GenerateKeypairForType(crypto.Curve25519Curve25519)
	require.NoError(b, err)

	data, err = vcrypto.Encrypt(data, keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = vcrypto.Decrypt(data, keypair); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptHybridCurveRound5(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 1)
	rand.Read(data)

	keypair, err := vcrypto.GenerateKeypairForType(crypto.Curve25519Round5)
	require.NoError(b, err)

	data, err = vcrypto.Encrypt(data, keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = vcrypto.Decrypt(data, keypair); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignAndEncrypt(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerKeypair, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vcrypto.SignAndEncrypt(data, signerKeypair, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptAndVerify(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	recipientSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	recipientPk := recipientSk.PublicKey()

	signerSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	data, err = vcrypto.SignAndEncrypt(data, signerSk, recipientPk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = vcrypto.DecryptAndVerify(data, recipientSk, signerPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignThenEncrypt(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerKeypair, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vcrypto.SignThenEncrypt(data, signerKeypair, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptThenVerify(b *testing.B) {
	vcrypto := &crypto.Crypto{}

	// make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerSk, err := vcrypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	data, err = vcrypto.SignThenEncrypt(data, signerSk, encryptPk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = vcrypto.DecryptThenVerify(data, encryptSk, signerPk); err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark1000Recipients(b *testing.B) {
	vcrypto := &crypto.Crypto{}
	n := 1000
	keys := make([]crypto.PublicKey, 0, n)
	var kp crypto.PrivateKey
	var err error
	for i := 0; i < n; i++ {
		kp, err = vcrypto.GenerateKeypairForType(crypto.Ed25519)
		require.NoError(b, err)
		keys = append(keys, kp.PublicKey())
	}
	data := make([]byte, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vcrypto.SignThenEncryptWithPadding(data, kp, true, keys...)
		require.NoError(b, err)
		// fmt.Println(len(ct))
	}
}
