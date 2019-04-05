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

package virgil.crypto.phe;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PheCipherTest {

	private PheCipher cipher;

	@Before
	public void setup() {
		this.cipher = new PheCipher();
	}

	@After
	public void teardown() {
		this.cipher.close();
	}

	@Test
	public void testFullFlowShouldSucceed() throws PheException {
		byte[] plainText = "plain text".getBytes(StandardCharsets.UTF_8);
		byte[] accountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC".getBytes(StandardCharsets.UTF_8); // 32 bytes string

		assertEquals(32, accountKey.length);

		this.cipher.setupDefaults();

		byte[] encryptedData = this.cipher.encrypt(plainText, accountKey);
		byte[] decryptedData = this.cipher.decrypt(encryptedData, accountKey);

		assertArrayEquals(plainText, decryptedData);
	}

	@Test
	public void testFullFlowWrongKeyShouldFail() throws PheException {
		byte[] plainText = "plain text".getBytes(StandardCharsets.UTF_8);
		byte[] accountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC".getBytes(StandardCharsets.UTF_8);
		byte[] wrongAccountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjD".getBytes(StandardCharsets.UTF_8);

		this.cipher.setupDefaults();
		byte[] encryptedData = this.cipher.encrypt(plainText, accountKey);
		try {
			this.cipher.decrypt(encryptedData, wrongAccountKey);
			fail();
		} catch (PheException e) {
			assertEquals(PheException.ERROR_AES_FAILED, e.getStatusCode());
		}
	}

}
