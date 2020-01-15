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

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

import com.virgilsecurity.crypto.foundation.AlgId;
import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.RecipientCipher;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class RecipientCipherBenchmark {

	private static final byte[] DATA = "this string will be encrypted".getBytes(StandardCharsets.UTF_8);
	private static final byte[] RECIPIENT_ID = "2e8176ba-34db-4c65-b977-c5eac687c4ac".getBytes(StandardCharsets.UTF_8);

	private RecipientCipher recipientCipher;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	private byte[] encryptedData;

	@Param({ "ED25519", "CURVE25519", "SECP256R1", "RSA" })
	private AlgId algId;

	@Param({ "4096" })
	private int bitlen;

	@Setup(Level.Invocation)
	public void setup() {
		try (KeyProvider keyProvider = new KeyProvider()) {
			keyProvider.setupDefaults();
			if (this.algId == AlgId.RSA) {
				keyProvider.setRsaParams(this.bitlen);
			}

			this.privateKey = keyProvider.generatePrivateKey(this.algId);
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

	@TearDown(Level.Invocation)
	public void tearDown() {
		this.recipientCipher.close();
		try {
			((AutoCloseable) this.privateKey).close();
			((AutoCloseable) this.publicKey).close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Benchmark
	public void encrypt() {
		this.recipientCipher.startEncryption();
		this.recipientCipher.packMessageInfo();
		this.recipientCipher.processEncryption(DATA);
		this.recipientCipher.finishEncryption();
	}

	@Benchmark
	public void decrypt() {
		this.recipientCipher.startDecryptionWithKey(RECIPIENT_ID, this.privateKey, new byte[0]);
		this.recipientCipher.processDecryption(this.encryptedData);
		this.recipientCipher.finishDecryption();
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

}
