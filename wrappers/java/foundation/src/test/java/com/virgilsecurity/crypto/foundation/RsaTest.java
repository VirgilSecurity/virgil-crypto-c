/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RsaTest extends SampleBasedTest {

	private Rsa rsa;
	private KeyProvider keyProvider;
	private int bitlen = 2048;

	@Before
	public void init() {
		this.rsa = new Rsa();
		this.rsa.setupDefaults();

		this.keyProvider = new KeyProvider();
		this.keyProvider.setupDefaults();
	}

	@After
	public void tearDown() {
		this.rsa.close();
		this.keyProvider.close();
	}

	@Test
	public void generateKey() {
		PrivateKey privateKey = this.rsa.generateKey(bitlen);
		assertNotNull(privateKey);
		assertEquals(AlgId.RSA, privateKey.algId());
		assertEquals(this.bitlen, privateKey.bitlen());
	}

	@Test
	public void canSign() {
		PrivateKey privateKey = this.rsa.generateKey(bitlen);
		assertTrue(this.rsa.canSign(privateKey));
	}

	@Test
	public void canSign_wrongKey() {
		try (Ed25519 ed = new Ed25519()) {
			ed.setupDefaults();
			PrivateKey privateKey = ed.generateKey();
			assertFalse(this.rsa.canSign(privateKey));
		}
	}

	@Test
	public void getCanExportPrivateKey() {
		assertTrue(this.rsa.getCanExportPrivateKey());
	}

	@Test
	public void getCanImportPrivateKey() {
		assertTrue(this.rsa.getCanImportPrivateKey());
	}

	@Test
	public void export_import_PrivateKey() {
		PrivateKey privateKey = this.rsa.generateKey(bitlen);

		// Export private key
		RawPrivateKey rawPrivateKey = this.rsa.exportPrivateKey(privateKey);
		assertNotNull(rawPrivateKey);

		byte[] exportedKeyData = rawPrivateKey.data();
		assertNotNull(exportedKeyData);

		try (RsaPrivateKey importedPrivateKey = (RsaPrivateKey) this.rsa.importPrivateKey(rawPrivateKey)) {
			RawPrivateKey rawPrivateKey2 = this.rsa.exportPrivateKey(importedPrivateKey);
			assertNotNull(rawPrivateKey2);

			byte[] exportedKeyData2 = rawPrivateKey2.data();
			assertNotNull(exportedKeyData2);
			assertArrayEquals(exportedKeyData, exportedKeyData2);
		}
	}

	@Test
	public void export_import_PublicKey() {
		PrivateKey privateKey = this.rsa.generateKey(bitlen);
		PublicKey publicKey = privateKey.extractPublicKey();

		// Export private key
		RawPublicKey rawPublicKey = this.rsa.exportPublicKey(publicKey);
		assertNotNull(rawPublicKey);

		byte[] exportedKeyData = rawPublicKey.data();
		assertNotNull(exportedKeyData);

		try (RsaPublicKey importedPublicKey = (RsaPublicKey) this.rsa.importPublicKey(rawPublicKey)) {
			RawPublicKey rawPublicKey2 = this.rsa.exportPublicKey(importedPublicKey);
			assertNotNull(rawPublicKey2);

			byte[] exportedKeyData2 = rawPublicKey2.data();
			assertNotNull(exportedKeyData2);
			assertArrayEquals(exportedKeyData, exportedKeyData2);
		}
	}

	@Test
	public void encrypt_decrypt() {
		byte[] data = new byte[100];
		new Random().nextBytes(data);

		try (RsaPrivateKey privateKey = (RsaPrivateKey) this.rsa.generateKey(this.bitlen);
				RsaPublicKey publicKey = (RsaPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.rsa.canEncrypt(publicKey, data.length));

			byte[] encryptedData = this.rsa.encrypt(publicKey, data);
			assertNotNull(encryptedData);

			assertTrue(this.rsa.canDecrypt(privateKey, encryptedData.length));

			byte[] decryptedData = this.rsa.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);

			assertArrayEquals(data, decryptedData);
		}
	}

	@Test
	public void decrypt() {
		byte[] privateKeyData = getBytes("rsa.private_key");
		byte[] encryptedData = getBytes("rsa.encrypted_data");
		byte[] expectedDecryptedData = getBytes("short_data");

		try (RsaPrivateKey privateKey = (RsaPrivateKey) keyProvider.importPrivateKey(privateKeyData)) {

			byte[] decryptedData = this.rsa.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);
			assertArrayEquals(expectedDecryptedData, decryptedData);
		}
	}

	@Test
	public void sign() {
		byte[] data = getBytes("data");
		byte[] privateKeyData = getBytes("rsa.private_key");

		try (RsaPrivateKey privateKey = (RsaPrivateKey) keyProvider.importPrivateKey(privateKeyData);
				RsaPublicKey publicKey = (RsaPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.rsa.canSign(privateKey));

			byte[] signature = this.rsa.signHash(privateKey, AlgId.SHA512, data);
			assertNotNull(signature);
			assertEquals(this.rsa.signatureLen(privateKey), signature.length);

			assertTrue(this.rsa.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	public void verifyHash() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("rsa.public_key");
		byte[] signature = getBytes("rsa.signature");

		try (RsaPublicKey publicKey = (RsaPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertTrue(this.rsa.canVerify(publicKey));

			assertTrue(this.rsa.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	public void verifyHash_wrongSignature() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("rsa.public_key");
		byte[] signature = getBytes("rsa.wrong_signature");

		try (RsaPublicKey publicKey = (RsaPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertFalse(this.rsa.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

}
