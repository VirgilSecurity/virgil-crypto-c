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
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

public class Base64Test extends SampleBasedTest {

	@Before
	public void setup() {
	}

	@Test
	public void encode() {
		byte[] data = getBytes("data");
		byte[] expectedEncodedData = getString("data").getBytes();

		byte[] encodedData = Base64.encode(data);

		assertNotNull(encodedData);
		assertArrayEquals(expectedEncodedData, encodedData);
	}

	@Test
	public void encodedLen() {
		assertEquals(0, Base64.encodedLen(0));
		assertEquals(5, Base64.encodedLen(1));
		assertEquals(9, Base64.encodedLen(4));
	}

	@Test
	public void decode() {
		byte[] expectedDecodedData = getBytes("data");
		byte[] encodedData = getString("data").getBytes();

		byte[] decodedData = Base64.decode(encodedData);

		assertNotNull(decodedData);
		assertArrayEquals(expectedDecodedData, decodedData);
	}

	@Test
	public void decodedLen() {
		assertEquals(0, Base64.decodedLen(0));
		assertEquals(4, Base64.decodedLen(1));
	}

}
