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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class Ed25519Test extends SampleBasedTest {

	private Ed25519 ed;
	private KeyProvider keyProvider;

	@Before
	public void init() {
		this.ed = new Ed25519();
		this.ed.setupDefaults();

		this.keyProvider = new KeyProvider();
		this.keyProvider.setupDefaults();
	}

	@After
	public void tearDown() {
		this.ed.close();
		this.keyProvider.close();
	}

	@Test
	public void generateKey() {
		PrivateKey privateKey = this.ed.generateKey();
		assertNotNull(privateKey);
		assertEquals(AlgId.ED25519, privateKey.algId());
	}

	@Test
	public void algId() {
		assertEquals(AlgId.ED25519, this.ed.algId());
	}

	@Test
	public void canSign() {
		PrivateKey privateKey = this.ed.generateKey();
		assertTrue(this.ed.canSign(privateKey));
	}

	@Test
	public void canSign_wrongKey() {
		try (Rsa rsa = new Rsa()) {
			rsa.setupDefaults();
			PrivateKey privateKey = rsa.generateKey(2048);
			assertFalse(this.ed.canSign(privateKey));
		}
	}

	@Test
	public void getCanExportPrivateKey() {
		assertTrue(this.ed.getCanExportPrivateKey());
	}

	@Test
	public void getCanImportPrivateKey() {
		assertTrue(this.ed.getCanImportPrivateKey());
	}

	@Test
	public void export_import_PrivateKey() {
		PrivateKey privateKey = this.ed.generateKey();

		// Export private key
		RawPrivateKey rawPrivateKey = this.ed.exportPrivateKey(privateKey);
		assertNotNull(rawPrivateKey);

		byte[] exportedKeyData = rawPrivateKey.data();
		assertNotNull(exportedKeyData);

		try (RawPrivateKey importedPrivateKey = (RawPrivateKey) this.ed.importPrivateKey(rawPrivateKey)) {
			RawPrivateKey rawPrivateKey2 = this.ed.exportPrivateKey(importedPrivateKey);
			assertNotNull(rawPrivateKey2);

			byte[] exportedKeyData2 = rawPrivateKey2.data();
			assertNotNull(exportedKeyData2);
			assertArrayEquals(exportedKeyData, exportedKeyData2);
		}
	}

	@Test
	public void export_import_PublicKey() {
		PrivateKey privateKey = this.ed.generateKey();
		PublicKey publicKey = privateKey.extractPublicKey();

		// Export private key
		RawPublicKey rawPublicKey = this.ed.exportPublicKey(publicKey);
		assertNotNull(rawPublicKey);

		byte[] exportedKeyData = rawPublicKey.data();
		assertNotNull(exportedKeyData);

		try (RawPublicKey importedPublicKey = (RawPublicKey) this.ed.importPublicKey(rawPublicKey)) {
			RawPublicKey rawPublicKey2 = this.ed.exportPublicKey(importedPublicKey);
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

		try (RawPrivateKey privateKey = (RawPrivateKey) this.ed.generateKey();
				RawPublicKey publicKey = (RawPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.ed.canEncrypt(publicKey, data.length));

			byte[] encryptedData = this.ed.encrypt(publicKey, data);
			assertNotNull(encryptedData);

			assertTrue(this.ed.canDecrypt(privateKey, encryptedData.length));

			byte[] decryptedData = this.ed.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);

			assertArrayEquals(data, decryptedData);
		}
	}

	@Test
	public void decrypt() {
		byte[] privateKeyData = getBytes("ed25519.private_key");
		byte[] encryptedData = getBytes("ed25519.encrypted_data");
		byte[] expectedDecryptedData = getBytes("short_data");

		try (RawPrivateKey privateKey = (RawPrivateKey) keyProvider.importPrivateKey(privateKeyData)) {

			byte[] decryptedData = this.ed.decrypt(privateKey, encryptedData);
			assertNotNull(decryptedData);
			assertArrayEquals(expectedDecryptedData, decryptedData);
		}
	}

	@Test
	public void sign() {
		byte[] data = getBytes("data");
		byte[] privateKeyData = getBytes("ed25519.private_key");

		try (RawPrivateKey privateKey = (RawPrivateKey) keyProvider.importPrivateKey(privateKeyData);
				RawPublicKey publicKey = (RawPublicKey) privateKey.extractPublicKey()) {

			assertTrue(this.ed.canSign(privateKey));

			byte[] signature = this.ed.signHash(privateKey, AlgId.SHA512, data);
			assertNotNull(signature);
			assertEquals(this.ed.signatureLen(privateKey), signature.length);

			assertTrue(this.ed.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	public void verifyHash() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("ed25519.public_key");
		byte[] signature = getBytes("ed25519.signature");

		try (RawPublicKey publicKey = (RawPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertTrue(this.ed.canVerify(publicKey));

			assertTrue(this.ed.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

	@Test
	public void verifyHash_wrongSignature() {
		byte[] data = getBytes("data");
		byte[] publicKeyData = getBytes("ed25519.public_key");
		byte[] signature = getBytes("ed25519.wrong_signature");

		try (RawPublicKey publicKey = (RawPublicKey) keyProvider.importPublicKey(publicKeyData)) {
			assertFalse(this.ed.verifyHash(publicKey, AlgId.SHA512, data, signature));
		}
	}

}
