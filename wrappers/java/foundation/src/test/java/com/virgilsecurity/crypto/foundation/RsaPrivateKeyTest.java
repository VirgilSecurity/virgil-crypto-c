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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RsaPrivateKeyTest extends SampleBasedTest {

	private Rsa rsa;
	private RsaPrivateKey privateKey;
	private int bitlen = 2048;

	@Before
	public void init() {
		this.rsa = new Rsa();
		this.rsa.setupDefaults();

		this.privateKey = (RsaPrivateKey) this.rsa.generateKey(this.bitlen);
	}

	@After
	public void tearDown() {
		this.rsa.close();
		this.privateKey.close();
	}

	@Test
	public void algId() {
		assertEquals(AlgId.RSA, this.privateKey.algId());
	}

	@Test
	public void len() {
		assertEquals(this.bitlen / 8, this.privateKey.len());
	}

	@Test
	public void bitlen() {
		assertEquals(this.bitlen, this.privateKey.bitlen());
	}

	@Test
	public void extractPublicKey() {
		RsaPublicKey publicKey = (RsaPublicKey) this.privateKey.extractPublicKey();

		assertNotNull(publicKey);
	}
}
