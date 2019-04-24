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
import static org.junit.Assert.assertTrue;

import java.util.Base64;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class RsaPrivateKeyTest extends SampleBasedTest {

	private RsaPrivateKey privateKey;

	@Before
	public void init() {
		this.privateKey = new RsaPrivateKey();
		this.privateKey.setupDefaults();
		this.privateKey.setKeygenParams(2048);
	}

	@Test
	public void algId() {
		assertEquals(AlgId.RSA, this.privateKey.algId());
	}

	@Test
	public void keyLen() {
		// Key is no generated yet
		assertEquals(0, this.privateKey.keyLen());
	}

	@Test
	public void keyBitlen() {
		assertEquals(0, this.privateKey.keyBitlen());
	}

	@Test
	public void generateKey() {
		this.privateKey.generateKey();
		assertEquals(getInt("rsa.key_len"), this.privateKey.keyLen());
		assertEquals(getInt("rsa.key_bit_len"), this.privateKey.keyBitlen());
	}

	@Test
	@Ignore
	public void decrypt() {
		byte[] key = getBytes("rsa.private_key");
		byte[] encryptedData = getBytes("rsa.encrypted_data");
		byte[] expectedDecryptedData = getBytes("data");

		this.privateKey.importPrivateKey(key);

		byte[] decryptedData = this.privateKey.decrypt(encryptedData);

		assertNotNull(decryptedData);
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	@Ignore
	public void sign() {
		byte[] data = getBytes("data");
		byte[] key = getBytes("rsa.private_key");
		byte[] expectedSignature = getBytes("rsa.signature");

		this.privateKey.importPrivateKey(key);

		byte[] signature = this.privateKey.signHash(data, this.privateKey.algId());

		assertNotNull(signature);
		System.out.println(Base64.getEncoder().encodeToString(signature));
		assertArrayEquals(expectedSignature, signature);
	}

	@Test
	public void signatureLen() {
		assertEquals(getBytes("rsa.signature").length, this.privateKey.signatureLen());
	}

	@Test
	public void export_import() {
		this.privateKey.generateKey();

		// Export private key
		byte[] exportedKey = this.privateKey.exportPrivateKey();
		assertNotNull(exportedKey);

		try (RsaPrivateKey importedPrivateKey = new RsaPrivateKey()) {
			// Import private key
			importedPrivateKey.setupDefaults();
			importedPrivateKey.importPrivateKey(exportedKey);

			byte[] exportedKey2 = importedPrivateKey.exportPrivateKey();

			assertNotNull(exportedKey2);
			assertArrayEquals(exportedKey, exportedKey2);
		}
	}

	@Test
	public void getCanExportPrivateKey() {
		assertTrue(this.privateKey.getCanExportPrivateKey());
	}

	@Test
	public void getCanImportPrivateKey() {
		assertTrue(this.privateKey.getCanImportPrivateKey());
	}

	@Test
	public void extractPublicKey() {
		this.privateKey.generateKey();
		RsaPublicKey publicKey = (RsaPublicKey) this.privateKey.extractPublicKey();

		assertNotNull(publicKey);
	}
}
