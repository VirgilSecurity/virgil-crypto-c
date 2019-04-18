/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
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

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Aes256CbcTest extends SampleBasedTest {

	private Aes256Cbc aes;

	@Before
	public void init() {
		this.aes = new Aes256Cbc();
	}

	@Test
	public void encrypt() {
		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));

		byte[] encryptedData = this.aes.encrypt(getBytes("data"));

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_cbc.encrypted_data"), encryptedData);
	}

	@Test
	public void encryptWithCipher() {
		byte[] data = getBytes("data");

		byte[] encryptedData = null;

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));
		this.aes.startEncryption();

		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.update(data));
		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.finish());

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_cbc.encrypted_data"), encryptedData);
	}

	@Test
	public void decryptWithCipher() {
		byte[] encryptedData = getBytes("aes256_cbc.encrypted_data");
		byte[] decryptedData = null;

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));
		this.aes.startDecryption();

		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.update(encryptedData));
		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.finish());

		assertNotNull(decryptedData);
		assertArrayEquals(getBytes("data"), decryptedData);
	}

	@Test
	public void decrypt() {
		byte[] expectedDecryptedData = getBytes("data");

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));

		byte[] decryptedData = this.aes.decrypt(getBytes("aes256_cbc.encrypted_data"));

		assertNotNull(decryptedData);
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	public void getNonceLen() {
		assertEquals(getInt("aes256_cbc.nonce_len"), this.aes.getNonceLen());
	}

	@Test
	public void getKeyLen() {
		assertEquals(getInt("aes256_cbc.key_len"), this.aes.getKeyLen());
	}

	@Test
	public void getKeyBitlen() {
		assertEquals(getInt("aes256_cbc.key_bit_len"), this.aes.getKeyBitlen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("aes256_cbc.block_len"), this.aes.getBlockLen());
	}

}
