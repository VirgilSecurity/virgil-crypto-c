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
import com.virgilsecurity.crypto.foundation.CtrDrbg;
import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.Sha384;
import com.virgilsecurity.crypto.foundation.Signer;
import com.virgilsecurity.crypto.foundation.Verifier;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class SignatureBenchmark {

	private static final byte[] DATA = "this string will be signed".getBytes(StandardCharsets.UTF_8);

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signer signer;
	private Verifier verifier;

	@Param({ "ED25519", "SECP256R1", "RSA" })
	private AlgId algId;

	@Param({ "4096" })
	private int bitlen;

	private byte[] signature;

	@Setup(Level.Invocation)
	public void setup() {
		CtrDrbg ctrDrbg = new CtrDrbg();
		ctrDrbg.setupDefaults();

		try (KeyProvider keyProvider = new KeyProvider()) {
			keyProvider.setupDefaults();
			if (this.algId == AlgId.RSA) {
				keyProvider.setRsaParams(this.bitlen);
			}

			this.privateKey = keyProvider.generatePrivateKey(this.algId);
			this.publicKey = this.privateKey.extractPublicKey();
		}

		this.signer = new Signer();
		this.signer.setRandom(ctrDrbg);
		this.signer.setHash(new Sha384());

		this.signer.reset();
		this.signer.appendData(DATA);
		this.signature = this.signer.sign(this.privateKey);

		this.verifier = new Verifier();
	}

	@TearDown(Level.Invocation)
	public void tearDown() {
		try {
			((AutoCloseable) this.signer).close();
			((AutoCloseable) this.privateKey).close();
			((AutoCloseable) this.publicKey).close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Benchmark
	public void sign() {
		this.signer.reset();
		this.signer.appendData(DATA);
		this.signer.sign(this.privateKey);
	}

	@Benchmark
	public void verify() {
		this.verifier.reset(this.signature);
		this.verifier.appendData(DATA);
		this.verifier.verify(this.publicKey);
	}

}
