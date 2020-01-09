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
import org.junit.Ignore;
import org.junit.Test;

public class EccTest extends SampleBasedTest {

	private AlgId algId;
	private com.virgilsecurity.crypto.foundation.Random random;
	private Ecc ecc;
	private KeyProvider keyProvider;

	@Before
	public void init() {
		this.algId = AlgId.SECP256R1;
		this.random = new CtrDrbg();
		this.ecc = new Ecc();
		this.ecc.setupDefaults();

		this.keyProvider = new KeyProvider();
		this.keyProvider.setupDefaults();
	}

	@After
	public void tearDown() {
		this.ecc.close();
		this.keyProvider.close();
	}

	@Test
	public void generateKey() {
		PrivateKey privateKey = this.ecc.generateKey(this.algId);
		assertNotNull(privateKey);
		assertEquals(this.algId, privateKey.algId());
	}

	@Test
	public void canSign() {
		PrivateKey privateKey = this.ecc.generateKey(this.algId);
		assertTrue(this.ecc.canSign(privateKey));
	}

	@Test
	public void canSign_wrongKey() {
		try (Rsa rsa = new Rsa()) {
			rsa.setupDefaults();
			PrivateKey privateKey = rsa.generateKey(2048);
			assertFalse(this.ecc.canSign(privateKey));
		}
	}

	@Test
	public void getCanExportPrivateKey() {
		assertTrue(this.ecc.getCanExportPrivateKey());
	}

	@Test
	public void getCanImportPrivateKey() {
		assertTrue(this.ecc.getCanImportPrivateKey());
	}

	@Test
	public void export_import_PrivateKey() {
		PrivateKey privateKey = this.ecc.generateKey(this.algId);

		// Export private key
		RawPrivateKey rawPrivateKey = this.ecc.exportPrivateKey(privateKey);
		assertNotNull(rawPrivateKey);

		byte[] exportedKeyData = rawPrivateKey.data();
		assertNotNull(exportedKeyData);

		try (EccPrivateKey importedPrivateKey = (EccPrivateKey) this.ecc.importPrivateKey(rawPrivateKey)) {
			RawPrivateKey rawPrivateKey2 = this.ecc.exportPrivateKey(importedPrivateKey);
			assertNotNull(rawPrivateKey2);

			byte[] exportedKeyData2 = rawPrivateKey2.data();
			assertNotNull(exportedKeyData2);
			assertArrayEquals(exportedKeyData, exportedKeyData2);
		}
	}

	@Test
	public void export_import_PublicKey() {
		PrivateKey privateKey = this.ecc.generateKey(this.algId);
		PublicKey publicKey = privateKey.extractPublicKey();

		// Export private key
		RawPublicKey rawPublicKey = this.ecc.exportPublicKey(publicKey);
		assertNotNull(rawPublicKey);

		byte[] exportedKeyData = rawPublicKey.data();
		assertNotNull(exportedKeyData);

		try (EccPublicKey importedPublicKey = (EccPublicKey) this.ecc.importPublicKey(rawPublicKey)) {
			RawPublicKey rawPublicKey2 = this.ecc.exportPublicKey(importedPublicKey);
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

		try (EccPrivateKey privateKey = (EccPrivateKey) this.ecc.generateKey(this.algId);
				EccPublicKey publicKey = (EccPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.ecc.canEncrypt(publicKey, data.length));

			byte[] encryptedData = this.ecc.encrypt(publicKey, data);
			assertNotNull(encryptedData);

			assertTrue(this.ecc.canDecrypt(privateKey, encryptedData.length));

			byte[] decryptedData = this.ecc.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);

			assertArrayEquals(data, decryptedData);
		}
	}

	@Test
	@Ignore
	public void decrypt() {
		byte[] privateKeyData = getBytes("ecc.private_key");
		byte[] encryptedData = getBytes("ecc.encrypted_data");
		byte[] expectedDecryptedData = getBytes("short_data");

		try (EccPrivateKey privateKey = (EccPrivateKey) keyProvider.importPrivateKey(privateKeyData)) {

			byte[] decryptedData = this.ecc.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);
			assertArrayEquals(expectedDecryptedData, decryptedData);
		}
	}

	@Test
	@Ignore
	public void sign() {
		byte[] data = getBytes("data");
		byte[] privateKeyData = getBytes("ecc.private_key");

		try (EccPrivateKey privateKey = (EccPrivateKey) keyProvider.importPrivateKey(privateKeyData);
				RawPublicKey publicKey = (RawPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.ecc.canSign(privateKey));

			byte[] signature = this.ecc.signHash(privateKey, AlgId.SHA512, data);
			assertNotNull(signature);
			assertEquals(this.ecc.signatureLen(privateKey), signature.length);

			assertTrue(this.ecc.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	@Ignore
	public void verifyHash() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("ecc.public_key");
		byte[] signature = getBytes("ecc.signature");

		try (RawPublicKey publicKey = (RawPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertTrue(this.ecc.canVerify(publicKey));

			assertTrue(this.ecc.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	@Ignore
	public void verifyHash_wrongSignature() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("ecc.public_key");
		byte[] signature = getBytes("ecc.wrong_signature");

		try (RawPublicKey publicKey = (RawPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertFalse(this.ecc.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	public void generateKey_exportPrivateKey_in_cycle() throws Exception {
		for (int i = 0; i < 1000; i++) {
			try (KeyAsn1Serializer serializer = new KeyAsn1Serializer()) {
				serializer.setupDefaults();
				PrivateKey privateKey = this.ecc.generateKey(this.algId);
				KeyAlg keyAlg = KeyAlgFactory.createFromKey(privateKey, this.random);
				try (RawPrivateKey rawPrivateKey = keyAlg.exportPrivateKey(privateKey)) {
					serializer.serializePrivateKey(rawPrivateKey);
				} finally {
					if (keyAlg instanceof AutoCloseable) {
						((AutoCloseable) keyAlg).close();
					}
				}
			}
		}
	}

}
