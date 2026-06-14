/*
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
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

package com.virgilsecurity.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;

public class ChunkCipherTest {

	// NIST AES-256 test key (same vector used in C test suite)
	private static final byte[] KEY = {
		(byte)0x60, (byte)0x3d, (byte)0xeb, (byte)0x10, (byte)0x15, (byte)0xca, (byte)0x71, (byte)0xbe,
		(byte)0x2b, (byte)0x73, (byte)0xae, (byte)0xf0, (byte)0x85, (byte)0x7d, (byte)0x77, (byte)0x81,
		(byte)0x1f, (byte)0x35, (byte)0x2c, (byte)0x07, (byte)0x3b, (byte)0x61, (byte)0x08, (byte)0xd7,
		(byte)0x2d, (byte)0x98, (byte)0x10, (byte)0xa3, (byte)0x09, (byte)0x14, (byte)0xdf, (byte)0xf4
	};

	@Test
	public void nonceLen() {
		try (ChunkCipher cipher = new ChunkCipher()) {
			assertEquals(12, cipher.nonceLen());
		}
	}

	@Test
	public void encryptDecrypt_partialChunk_roundtrip() throws FoundationException {
		byte[] plaintext = "Hello".getBytes();
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(32);
			enc.startEncryption();

			nonce = enc.nonce();
			assertEquals(12, nonce.length);

			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		assertNotNull(ciphertext);

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(32);
			dec.startDecryption();

			byte[] recovered = ArrayUtils.addAll(dec.processDecryption(ciphertext), dec.finishDecryption());
			assertArrayEquals(plaintext, recovered);
		}
	}

	@Test
	public void encryptDecrypt_exactlyOneChunk_roundtrip() throws FoundationException {
		byte[] plaintext = new byte[16];
		Arrays.fill(plaintext, (byte) 0x42);
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(16);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		// One 16-byte data frame (40 bytes) + one empty FIN frame (8+0+16=24 bytes) = 64 bytes
		assertEquals(64, ciphertext.length);

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(16);
			dec.startDecryption();

			byte[] recovered = ArrayUtils.addAll(dec.processDecryption(ciphertext), dec.finishDecryption());
			assertArrayEquals(plaintext, recovered);
		}
	}

	@Test
	public void encryptDecrypt_multiChunk_roundtrip() throws FoundationException {
		// 2 full chunks (16 bytes each) + 1 partial (7 bytes) = 39 bytes total
		byte[] plaintext = new byte[39];
		for (int i = 0; i < plaintext.length; i++) {
			plaintext[i] = (byte)(i & 0xFF);
		}
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(16);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		// 3 frames: 2*(16+24) + (7+24) = 80 + 31 = 111 bytes
		assertEquals(111, ciphertext.length);

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(16);
			dec.startDecryption();

			byte[] recovered = ArrayUtils.addAll(dec.processDecryption(ciphertext), dec.finishDecryption());
			assertArrayEquals(plaintext, recovered);
		}
	}

	@Test
	public void encryptDecrypt_defaultChunkSize_roundtrip() throws FoundationException {
		byte[] plaintext = new byte[100];
		for (int i = 0; i < plaintext.length; i++) {
			plaintext[i] = (byte)(i & 0xFF);
		}
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		assertNotNull(ciphertext);

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.startDecryption();

			byte[] recovered = ArrayUtils.addAll(dec.processDecryption(ciphertext), dec.finishDecryption());
			assertArrayEquals(plaintext, recovered);
		}
	}

	@Test(expected = FoundationException.class)
	public void decrypt_truncatedStream_authFails() throws FoundationException {
		// 2 full chunks (32 bytes with chunk_size=16) produce 2 data frames + 1 empty FIN frame.
		// Stripping the FIN frame must cause decryption to fail.
		byte[] plaintext = new byte[32];
		Arrays.fill(plaintext, (byte) 0x33);
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(16);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		// Strip the 24-byte FIN frame
		byte[] truncated = Arrays.copyOf(ciphertext, ciphertext.length - 24);

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(16);
			dec.startDecryption();

			dec.processDecryption(truncated);
			dec.finishDecryption(); // must throw
		}
	}

	@Test(expected = FoundationException.class)
	public void decrypt_tamperedChunkSize_authFails() throws FoundationException {
		// Encrypt with chunk_size=16; attempt to decrypt with chunk_size=32.
		// Frame 0 AAD includes chunk_size, so the mismatch must fail GCM authentication.
		byte[] plaintext = new byte[10];
		Arrays.fill(plaintext, (byte) 0x44);
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(16);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(32); // tampered: different from encryption chunk_size
			dec.startDecryption();

			dec.processDecryption(ciphertext);
			dec.finishDecryption(); // must throw
		}
	}

	@Test(expected = FoundationException.class)
	public void decrypt_tamperedCiphertext_authFails() throws FoundationException {
		byte[] plaintext = new byte[10];
		Arrays.fill(plaintext, (byte) 0x11);
		byte[] nonce;
		byte[] ciphertext;

		try (FakeRandom fakeRandom = new FakeRandom();
			 ChunkCipher enc = new ChunkCipher()) {
			fakeRandom.setupSourceByte((byte) 0xAB);
			enc.setRandom(fakeRandom);
			enc.setKey(KEY);
			enc.setChunkSize(16);
			enc.startEncryption();

			nonce = enc.nonce();
			ciphertext = ArrayUtils.addAll(enc.processEncryption(plaintext), enc.finishEncryption());
		}

		// Flip first ciphertext byte (byte 8, after the 8-byte counter)
		ciphertext[8] ^= (byte) 0xFF;

		try (ChunkCipher dec = new ChunkCipher()) {
			dec.setKey(KEY);
			dec.setNonce(nonce);
			dec.setChunkSize(16);
			dec.startDecryption();

			dec.processDecryption(ciphertext);
			dec.finishDecryption();
		}
	}

}
