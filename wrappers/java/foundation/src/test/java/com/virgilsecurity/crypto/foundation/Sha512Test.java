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
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Sha512Test extends SampleBasedTest {

	private Sha512 sha512;

	@Before
	public void init() {
		this.sha512 = new Sha512();
	}

	@Test
	public void algId() {
		AlgId algId = this.sha512.algId();
		assertNotNull(algId);
		assertEquals(AlgId.SHA512, algId);
	}

	@Test
	public void getDigestLen() {
		assertEquals(getInt("sha512.digest_len"), this.sha512.getDigestLen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("sha512.block_len"), this.sha512.getBlockLen());
	}

	@Test
	public void hash() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha512.hash");

		byte[] hash = this.sha512.hash(data);

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void hashStream() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha512.hash");

		this.sha512.start();

		int blockLen = this.sha512.getBlockLen();
		for (int startIndex = 0; startIndex < data.length; startIndex += blockLen) {
			byte[] block = ArrayUtils.subarray(data, startIndex, startIndex + blockLen);
			this.sha512.update(block);
		}

		byte[] hash = this.sha512.finish();

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

}
