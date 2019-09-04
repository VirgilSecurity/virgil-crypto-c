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

import android.support.test.runner.AndroidJUnit4;
import android.util.Log;
import com.virgilsecurity.crypto.benchmark.BenchmarkOptions;
import com.virgilsecurity.crypto.foundation.AlgId;
import com.virgilsecurity.crypto.foundation.CtrDrbg;
import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.RsaPrivateKey;
import com.virgilsecurity.crypto.foundation.Sha384;
import com.virgilsecurity.crypto.foundation.Signer;
import com.virgilsecurity.crypto.foundation.Verifier;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class SignatureBenchmark {

	private static final byte[] DATA = "this string will be signed".getBytes(StandardCharsets.UTF_8);

	private AlgId algId;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signer signer;
	private Verifier verifier;

	private byte[] signature;

	@Test
	public void sign_ed25519() {
		setup(AlgId.ED25519);
		sign();
	}

	@Test
	public void sign_secp256r1() {
		setup(AlgId.SECP256R1);
		sign();
	}

	@Test
	@Ignore
	public void sign_rsa() {
		setup(AlgId.RSA);
		sign();
	}

	@Test
	public void verify_ed25519() {
		setup(AlgId.ED25519);
		verify();
	}

	@Test
	public void verify_secp256r1() {
		setup(AlgId.SECP256R1);
		verify();
	}

	@Test
	@Ignore
	public void verify_rsa() {
		setup(AlgId.RSA);
		verify();
	}


	@After
	public void tearDown() {
		try {
			((AutoCloseable) this.signer).close();
			((AutoCloseable) this.privateKey).close();
			((AutoCloseable) this.publicKey).close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void setup(AlgId algId) {
		this.algId = algId;

		CtrDrbg ctrDrbg = new CtrDrbg();
		ctrDrbg.setupDefaults();

		try (KeyProvider keyProvider = new KeyProvider()) {
			keyProvider.setupDefaults();
			if (algId == AlgId.RSA) {
				keyProvider.setRsaParams(4096);
			}

			this.privateKey = keyProvider.generatePrivateKey(algId);
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

	private void sign() {
		long startTime = System.nanoTime();
		for (int i = BenchmarkOptions.MEASUREMENTS; i > 0; i--) {
			this.signer.reset();
			this.signer.appendData(DATA);
			this.signer.sign(this.privateKey);
		}
		long endTime = System.nanoTime();
		long avgTime = (endTime - startTime) / BenchmarkOptions.MEASUREMENTS;
		Log.i("Benchmark", "Sign with " + this.algId + " in " + avgTime + " ns");
	}

	private void verify() {
		KeyProvider provider = new KeyProvider();
		provider.setupDefaults();
		PrivateKey p = provider.generatePrivateKey(AlgId.ED25519);
		long startTime = System.nanoTime();
		for (int i = BenchmarkOptions.MEASUREMENTS; i > 0; i--) {
//			for (int j = 10000; j > 0; j--) {
//				RsaPrivateKey pp = new RsaPrivateKey();
//				try (AutoCloseable publicKey = (AutoCloseable)p.extractPublicKey()) {
//
//				} catch (Exception e) {
//					Log.i("", e.getMessage());
//				}
//			}
//			Log.i("VERIFY", "" + i);
			this.verifier.reset(this.signature);
			this.verifier.appendData(DATA);
			this.verifier.verify(this.publicKey);
		}
		long endTime = System.nanoTime();
		long avgTime = (endTime - startTime) / BenchmarkOptions.MEASUREMENTS;
		Log.i("Benchmark", "Verify with " + this.algId + " in " + avgTime + " ns");
	}

}
