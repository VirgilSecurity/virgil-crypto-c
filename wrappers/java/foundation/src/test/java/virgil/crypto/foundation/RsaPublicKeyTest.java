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

package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class RsaPublicKeyTest extends SampleBasedTest {

	private RsaPublicKey publicKey;

	@Before
	public void init() {
		this.publicKey = new RsaPublicKey();
		this.publicKey.setupDefaults();
	}

	@Test
	public void alg() {
		assertEquals(AlgId.RSA, this.publicKey.algId());
	}

	@Test
	public void keyLen() {
		assertEquals(0, this.publicKey.keyLen());
	}

	@Test
	public void keyBitlen() {
		assertEquals(0, this.publicKey.keyBitlen());
	}

	@Test
	public void importPublicKey() {
		this.publicKey.importPublicKey(getBytes("rsa.public_key"));

		assertEquals(getInt("rsa.key_len"), this.publicKey.keyLen());
		assertEquals(getInt("rsa.key_bit_len"), this.publicKey.keyBitlen());
	}

	@Test
	@Ignore
	public void encrypt() {
		byte[] keyData = getBytes("rsa.public_key");
		byte[] data = getBytes("data");
		byte[] expectedEncryptedData = getBytes("rsa.encrypted_data");

		this.publicKey.importPublicKey(keyData);
		this.publicKey.setupDefaults();

		byte[] encryptedData = this.publicKey.encrypt(data);

		assertNotNull(encryptedData);
		assertArrayEquals(expectedEncryptedData, encryptedData);
		java.util.Base64.getEncoder().encodeToString(encryptedData);
	}

	@Test
	public void encryptedLen() {
		int dataLen = getBytes("data").length;
		int encryptedDataLen = getBytes("rsa.encrypted_data").length;

		assertEquals(encryptedDataLen, this.publicKey.encryptedLen(dataLen));
	}

	@Test
	@Ignore
	public void verify() {
		byte[] data = getBytes("data");
		byte[] keyData = getBytes("rsa.public_key");
		byte[] signature = getBytes("rsa.signature");
		byte[] wrongSignature = getBytes("rsa.wrong_signature");

		this.publicKey.importPublicKey(keyData);

		assertTrue(this.publicKey.verifyHash(data, this.publicKey.algId(), signature));
		assertFalse(this.publicKey.verifyHash(data, this.publicKey.algId(), wrongSignature));
	}

	@Test
	public void export_import() {
		try (RsaPrivateKey privateKey = new RsaPrivateKey()) {
			privateKey.setKeygenParams(256, 3);
			privateKey.setupDefaults();
			privateKey.generateKey();
			byte[] keyData = privateKey.extractPublicKey().exportPublicKey();

			this.publicKey.importPublicKey(keyData);

			// Export public key
			byte[] exportedKey = this.publicKey.exportPublicKey();
			assertNotNull(exportedKey);
			assertArrayEquals(keyData, exportedKey);

			// Import public key
			try (RsaPublicKey importedPublicKey = new RsaPublicKey()) {
				importedPublicKey.setupDefaults();
				importedPublicKey.importPublicKey(exportedKey);
			}
		}
	}

	@Test
	public void getCanExportPublicKey() {
		assertTrue(this.publicKey.getCanExportPublicKey());
	}

	@Test
	public void getCanImportPublicKey() {
		assertTrue(this.publicKey.getCanImportPublicKey());
	}

}