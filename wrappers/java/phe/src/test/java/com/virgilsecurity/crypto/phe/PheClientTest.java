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

package com.virgilsecurity.crypto.phe;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PheClientTest {

	private PheClient client;
	private PheServer server;

	@Before
	public void setup() {
		this.client = new PheClient();
		this.client.setupDefaults();
		assertTrue("C context should be set", this.client.cCtx > 0);

		this.server = new PheServer();
		this.server.setupDefaults();
		assertTrue("C context should be set", this.server.cCtx > 0);
	}

	@After
	public void teardown() {
		this.client.close();
		this.server.close();
	}

	@Test
	public void testFullFlowRandomCorrectPwdShouldSucceed() throws PheException {
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);

		PheServerGenerateServerKeyPairResult serverKeyPair = server.generateServerKeyPair();
		assertNotNull(serverKeyPair);

		byte[] serverPrivateKey = serverKeyPair.getServerPrivateKey();
		assertNotNull(serverPrivateKey);
		assertEquals(32, serverPrivateKey.length);

		byte[] serverPublicKey = serverKeyPair.getServerPublicKey();
		assertNotNull(serverPublicKey);
		assertEquals(65, serverPublicKey.length);

		byte[] clientPrivateKey = this.client.generateClientPrivateKey(); // {privateKey}
		assertNotNull(clientPrivateKey);

		this.client.setKeys(clientPrivateKey, serverPublicKey); // void

		byte[] serverEnrollment = this.server.getEnrollment(serverPrivateKey, serverPublicKey);
		assertNotNull(serverEnrollment);
		assertTrue(serverEnrollment.length > 0);

		PheClientEnrollAccountResult clientEnrollAccount = this.client.enrollAccount(serverEnrollment, password);
		assertNotNull(clientEnrollAccount);

		byte[] clientEnrollmentRecord = clientEnrollAccount.getEnrollmentRecord();
		assertNotNull(clientEnrollmentRecord);

		byte[] clientAccountKey = clientEnrollAccount.getAccountKey();
		assertNotNull(clientAccountKey);
		assertEquals(32, clientAccountKey.length);

		byte[] clientCreateVerifyPasswordRequest = this.client.createVerifyPasswordRequest(password,
				clientEnrollmentRecord);
		assertNotNull(clientCreateVerifyPasswordRequest);
		assertTrue(clientCreateVerifyPasswordRequest.length > 0);

		byte[] serverVerifyPassword = this.server.verifyPassword(serverPrivateKey, serverPublicKey,
				clientCreateVerifyPasswordRequest);
		assertNotNull(serverVerifyPassword);

		byte[] clientCheckResponseAndDecrypt = this.client.checkResponseAndDecrypt(password, clientEnrollmentRecord,
				serverVerifyPassword);
		assertNotNull(clientCheckResponseAndDecrypt);
		assertEquals(32, clientCheckResponseAndDecrypt.length);
		assertArrayEquals(clientAccountKey, clientCheckResponseAndDecrypt);
	}

	@Test
	public void testRotationRandomRotationServerPublicKeysMatch() throws PheException {
		PheServerGenerateServerKeyPairResult serverKeyPair = this.server.generateServerKeyPair();
		assertNotNull(serverKeyPair);

		byte[] serverPrivateKey = serverKeyPair.getServerPrivateKey();
		assertNotNull(serverPrivateKey);

		byte[] serverPublicKey = serverKeyPair.getServerPublicKey();
		assertNotNull(serverPublicKey);

		PheServerRotateKeysResult serverRotateKeys = this.server.rotateKeys(serverPrivateKey);
		assertNotNull(serverRotateKeys);

		byte[] serverRotatedPrivateKey = serverRotateKeys.getNewServerPrivateKey();
		assertNotNull(serverRotatedPrivateKey);
		assertEquals(32, serverRotatedPrivateKey.length);

		byte[] serverRotatedPublicKey = serverRotateKeys.getNewServerPublicKey();
		assertNotNull(serverRotatedPublicKey);
		assertEquals(65, serverRotatedPublicKey.length);

		byte[] serverUpdateToken = serverRotateKeys.getUpdateToken();
		assertNotNull(serverUpdateToken);
		assertTrue(serverUpdateToken.length > 0);

		byte[] clientPrivateKey = this.client.generateClientPrivateKey();
		assertNotNull(clientPrivateKey);
		assertEquals(32, clientPrivateKey.length);

		this.client.setKeys(clientPrivateKey, serverRotatedPublicKey);

		PheClientRotateKeysResult clientRotateKeys = this.client.rotateKeys(serverUpdateToken);
		assertNotNull(clientRotateKeys);

		byte[] clientNewPrivateKey = clientRotateKeys.getNewClientPrivateKey();
		assertNotNull(clientNewPrivateKey);
		assertEquals(32, clientNewPrivateKey.length);

		byte[] serverNewPublicKey = clientRotateKeys.getNewServerPublicKey();
		assertNotNull(serverNewPublicKey);
		assertEquals(65, serverNewPublicKey.length);

		assertEquals(serverPublicKey.length, serverNewPublicKey.length);
		assertEquals(clientPrivateKey.length, clientNewPrivateKey.length);
	}

}
