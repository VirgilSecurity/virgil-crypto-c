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
import com.virgilsecurity.crypto.foundation.Hash;
import com.virgilsecurity.crypto.foundation.Sha256;
import com.virgilsecurity.crypto.foundation.Sha512;
import java.util.Random;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class HashBenchmark {

	private byte[] data;

	private AlgId algId;
	private Hash hash;

	@After
	public void tearDown() {
		try {
			((AutoCloseable) this.hash).close();
		} catch (Exception e) {
			Log.e("Hash", "Can't close hash resource", e);
		}
	}

	@Test
	public void hash_sha256() {
		setup(AlgId.SHA256);
		hash();
	}

	@Test
	public void hash_sha512() {
		setup(AlgId.SHA512);
		hash();
	}

	private void setup(AlgId algId) {
		this.algId = algId;

		this.data = new byte[8192];
		(new Random()).nextBytes(this.data);

		switch (algId) {
			case SHA256:
				this.hash = new Sha256();
				break;
			case SHA512:
				this.hash = new Sha512();
				break;
			default:
				break;
		}
	}

	private void hash() {
		long startTime = System.nanoTime();
		for (int i = BenchmarkOptions.MEASUREMENTS; i > 0; i--) {
			this.hash.start();
			this.hash.hash(data);
			this.hash.finish();
		}
		long endTime = System.nanoTime();
		long avgTime = (endTime - startTime) / BenchmarkOptions.MEASUREMENTS;
		Log.i("Benchmark", "Hash with " + this.algId + " in " + avgTime + " ns");
	}
}
