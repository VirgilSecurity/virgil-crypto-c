//  Copyright (C) 2015-2026 Virgil Security, Inc.
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
	"testing"

	"github.com/stretchr/testify/require"
)

func chunkCipherTestKeyNonce() ([]byte, []byte) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	return key, nonce
}

// Exercises the random-access seek API (EncryptAt/DecryptAt) end to end through
// cgo: 40 bytes with chunk_size 16 -> frames idx0(16), idx1(16), idx2(8, last).
// Chunks are decrypted out of order (middle chunk first) to prove random access.
func TestChunkCipher_SeekApi_RandomAccessRoundTrip(t *testing.T) {
	key, nonce := chunkCipherTestKeyNonce()
	pt := make([]byte, 40)
	for i := range pt {
		pt[i] = byte(i)
	}

	enc := NewChunkCipher()
	defer enc.Delete()
	enc.SetKey(key)
	enc.SetNonce(nonce)
	enc.SetChunkSize(16)

	f0, err := enc.EncryptAt(0, false, pt[0:16])
	require.Nil(t, err)
	f1, err := enc.EncryptAt(1, false, pt[16:32])
	require.Nil(t, err)
	f2, err := enc.EncryptAt(2, true, pt[32:40])
	require.Nil(t, err)

	dec := NewChunkCipher()
	defer dec.Delete()
	dec.SetKey(key)
	dec.SetNonce(nonce)
	dec.SetChunkSize(16)

	// Middle chunk first, without decrypting chunk 0.
	p1, err := dec.DecryptAt(1, false, f1)
	require.Nil(t, err)
	require.Equal(t, pt[16:32], p1)

	p0, err := dec.DecryptAt(0, false, f0)
	require.Nil(t, err)
	require.Equal(t, pt[0:16], p0)

	p2, err := dec.DecryptAt(2, true, f2)
	require.Nil(t, err)
	require.Equal(t, pt[32:40], p2)
}

// A frame presented at the wrong index must fail closed (the embedded counter is
// validated against the expected index), never returning wrong plaintext.
func TestChunkCipher_SeekApi_WrongIndexFailsClosed(t *testing.T) {
	key, nonce := chunkCipherTestKeyNonce()
	pt := make([]byte, 32)
	for i := range pt {
		pt[i] = byte(0x11)
	}

	enc := NewChunkCipher()
	defer enc.Delete()
	enc.SetKey(key)
	enc.SetNonce(nonce)
	enc.SetChunkSize(16)

	_, err := enc.EncryptAt(0, false, pt[0:16])
	require.Nil(t, err)
	f1, err := enc.EncryptAt(1, true, pt[16:32])
	require.Nil(t, err)

	dec := NewChunkCipher()
	defer dec.Delete()
	dec.SetKey(key)
	dec.SetNonce(nonce)
	dec.SetChunkSize(16)

	// Present frame-of-index-1 as index 0: counter mismatch -> error, no plaintext.
	_, err = dec.DecryptAt(0, false, f1)
	require.NotNil(t, err)
}

// A non-zero chunk decrypted with a mismatched chunk_size must fail closed:
// chunk_size is bound into every frame's AEAD associated data, so random-access
// decryption of any chunk authenticates the framing parameter.
func TestChunkCipher_SeekApi_ChunkSizeTamperFailsClosed(t *testing.T) {
	key, nonce := chunkCipherTestKeyNonce()
	pt := make([]byte, 32)
	for i := range pt {
		pt[i] = byte(0x77)
	}

	enc := NewChunkCipher()
	defer enc.Delete()
	enc.SetKey(key)
	enc.SetNonce(nonce)
	enc.SetChunkSize(16)

	_, err := enc.EncryptAt(0, false, pt[0:16])
	require.Nil(t, err)
	f1, err := enc.EncryptAt(1, true, pt[16:32])
	require.Nil(t, err)

	// Decryptor configured with a different chunk_size, same key/nonce.
	dec := NewChunkCipher()
	defer dec.Delete()
	dec.SetKey(key)
	dec.SetNonce(nonce)
	dec.SetChunkSize(32)

	_, err = dec.DecryptAt(1, true, f1)
	require.NotNil(t, err)
}

// Streaming encrypt -> streaming decrypt round trip across multiple chunks.
func TestChunkCipher_Streaming_MultiChunkRoundTrip(t *testing.T) {
	key, nonce := chunkCipherTestKeyNonce()
	pt := make([]byte, 100) // chunk_size 16 -> 6 full chunks + partial
	for i := range pt {
		pt[i] = byte(i)
	}

	enc := NewChunkCipher()
	defer enc.Delete()
	enc.SetKey(key)
	enc.SetNonce(nonce)
	enc.SetChunkSize(16)
	enc.StartEncryption()

	ct, err := enc.ProcessEncryption(pt)
	require.Nil(t, err)
	tail, err := enc.FinishEncryption()
	require.Nil(t, err)
	ct = append(ct, tail...)

	dec := NewChunkCipher()
	defer dec.Delete()
	dec.SetKey(key)
	dec.SetNonce(nonce)
	dec.SetChunkSize(16)
	dec.StartDecryption()

	out, err := dec.ProcessDecryption(ct)
	require.Nil(t, err)
	tail2, err := dec.FinishDecryption()
	require.Nil(t, err)
	out = append(out, tail2...)

	require.Equal(t, pt, out)
}
