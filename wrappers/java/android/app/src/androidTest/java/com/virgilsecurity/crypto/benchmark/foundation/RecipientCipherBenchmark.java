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

package com.virgilsecurity.crypto.benchmark.foundation;

import android.support.test.runner.AndroidJUnit4;
import android.util.Log;
import com.virgilsecurity.crypto.benchmark.BenchmarkOptions;
import com.virgilsecurity.crypto.foundation.AlgId;
import com.virgilsecurity.crypto.foundation.CtrDrbg;
import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.RecipientCipher;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RecipientCipherBenchmark {

	private static final byte[] DATA = "this string will be encrypted".getBytes(StandardCharsets.UTF_8);
	private static final byte[] RECIPIENT_ID = "2e8176ba-34db-4c65-b977-c5eac687c4ac".getBytes(StandardCharsets.UTF_8);

	private String algName;
	private RecipientCipher recipientCipher;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	private byte[] encryptedData;

	@After
	public void tearDown() {
		try {
			this.recipientCipher.close();
			((AutoCloseable) this.privateKey).close();
			((AutoCloseable) this.publicKey).close();
		} catch (Exception e) {
			Log.e(BenchmarkOptions.TAG, "Can't close cipher resources", e);
		}
	}

	@Test
	public void encrypt_ed25519() {
		setup(AlgId.ED25519);
		encrypt();
	}

	@Test
	public void encrypt_curve25519() {
		setup(AlgId.CURVE25519);
		encrypt();
	}

	@Test
	public void encrypt_secp256r1() {
		setup(AlgId.SECP256R1);
		encrypt();
	}

	@Test
	@Ignore
	public void encrypt_rsa() {
		setup(AlgId.RSA);
		encrypt();
	}

	@Test
	public void decrypt_ed25519() {
		setup(AlgId.ED25519);
		decrypt();
	}

	@Test
	public void decrypt_curve25519() {
		setup(AlgId.CURVE25519);
		decrypt();
	}

	@Test
	public void decrypt_secp256r1() {
		setup(AlgId.SECP256R1);
		decrypt();
	}

	@Test
	@Ignore
	public void decrypt_rsa() {
		setup(AlgId.RSA);
		decrypt();
	}

	@Test
	public void encrypt_curve25519_round5() {
		setup(new HybridKeyType(AlgId.CURVE25519, AlgId.ROUND5_ND_5KEM_5D));
		encrypt();
	}

	@Test
	public void decrypt_curve25519_round5() {
		setup(new HybridKeyType(AlgId.CURVE25519, AlgId.ROUND5_ND_5KEM_5D));
		decrypt();
	}

	public void setup(AlgId algId) {
		this.algName = "" + algId;

		try (KeyProvider keyProvider = new KeyProvider()) {
			keyProvider.setupDefaults();
			if (algId == AlgId.RSA) {
				keyProvider.setRsaParams(4096);
			}

			this.privateKey = keyProvider.generatePrivateKey(algId);
			this.publicKey = this.privateKey.extractPublicKey();
		}

		this.recipientCipher = new RecipientCipher();
		this.recipientCipher.addKeyRecipient(RECIPIENT_ID, this.publicKey);

		this.recipientCipher.startEncryption();
		byte[] messageInfo = this.recipientCipher.packMessageInfo();
		byte[] data = this.recipientCipher.processEncryption(DATA);
		byte[] finish = this.recipientCipher.finishEncryption();

		this.encryptedData = concatenate(messageInfo, concatenate(data, finish));
	}

	public void setup(HybridKeyType keyType) {
		this.algName = "" + keyType.cipherFirstKeyAlgId + "/" + keyType.cipherSecondKeyAlgId;

		try (KeyProvider keyProvider = new KeyProvider()) {
			keyProvider.setupDefaults();

			this.privateKey = keyProvider.generateHybridPrivateKey(keyType.cipherFirstKeyAlgId, keyType.cipherSecondKeyAlgId);
			this.publicKey = this.privateKey.extractPublicKey();
		}

		this.recipientCipher = new RecipientCipher();
		this.recipientCipher.addKeyRecipient(RECIPIENT_ID, this.publicKey);

		this.recipientCipher.startEncryption();
		byte[] messageInfo = this.recipientCipher.packMessageInfo();
		byte[] data = this.recipientCipher.processEncryption(DATA);
		byte[] finish = this.recipientCipher.finishEncryption();

		this.encryptedData = concatenate(messageInfo, concatenate(data, finish));
	}
	private void encrypt() {
		long startTime = System.nanoTime();
		for (int i = BenchmarkOptions.MEASUREMENTS; i > 0; i--) {
			this.recipientCipher.startEncryption();
			this.recipientCipher.packMessageInfo();
			this.recipientCipher.processEncryption(DATA);
			this.recipientCipher.finishEncryption();
		}
		long endTime = System.nanoTime();
		long avgTime = (endTime - startTime) / BenchmarkOptions.MEASUREMENTS;
		Log.i(BenchmarkOptions.TAG, "Encrypt with " + this.algName + " in " + avgTime + " ns");
	}

	private void decrypt() {
		long startTime = System.nanoTime();
		for (int i = BenchmarkOptions.MEASUREMENTS; i > 0; i--) {
			this.recipientCipher.startDecryptionWithKey(RECIPIENT_ID, this.privateKey, new byte[0]);
			this.recipientCipher.processDecryption(this.encryptedData);
			this.recipientCipher.finishDecryption();
		}
		long endTime = System.nanoTime();
		long avgTime = (endTime - startTime) / BenchmarkOptions.MEASUREMENTS;
		Log.i(BenchmarkOptions.TAG, "Decrypt with " + this.algName + " in " + avgTime + " ns");
	}

	/**
	 * Concatenate two byte arrays.
	 *
	 * @param first  the first array.
	 * @param second the second array.
	 *
	 * @return a byte array.
	 */
	private byte[] concatenate(byte[] first, byte[] second) {
		byte[] result = new byte[first.length + second.length];
		System.arraycopy(first, 0, result, 0, first.length);
		System.arraycopy(second, 0, result, first.length, second.length);

		return result;
	}

	private class HybridKeyType {
		AlgId cipherFirstKeyAlgId;
		AlgId cipherSecondKeyAlgId;

		HybridKeyType (AlgId cipherFirstKeyAlgId, AlgId cipherSecondKeyAlgId) {
			this.cipherFirstKeyAlgId = cipherFirstKeyAlgId;
			this.cipherSecondKeyAlgId = cipherSecondKeyAlgId;
		}
	}
}
