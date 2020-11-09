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

import org.junit.Before;
import org.junit.Test;

public class BinaryTest extends SampleBasedTest {

	@Before
	public void setup() {
	}

	@Test
	public void toHex() {
		byte[] data = getBytes("data");
		String expectedHex = getString("binary.hex");

		String hex = Binary.toHex(data);

		assertNotNull(hex);
		assertEquals(expectedHex, hex);
	}

	@Test
	public void toHexLen() {
		int dataLen = getBytes("data").length;
		int expectedHexLen = getInt("binary.hexLen");

		int hexLen = Binary.toHexLen(dataLen);

		assertEquals(expectedHexLen, hexLen);
	}

	@Test
	public void fromHex() {
		String hex = getString("binary.hex");
		byte[] expectedData = getBytes("data");

		byte[] data = Binary.fromHex(hex);

		assertNotNull(hex);
		assertArrayEquals(expectedData, data);
	}

	@Test
	public void fromHexLen() {
		int hexLen = getString("binary.hex").length();
		int expectedDataLen = getInt("binary.dataLen");

		int dataLen = Binary.fromHexLen(hexLen);

		assertEquals(expectedDataLen, dataLen);
	}
}
