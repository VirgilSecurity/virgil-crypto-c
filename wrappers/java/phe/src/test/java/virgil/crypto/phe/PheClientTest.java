package virgil.crypto.phe;

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

		byte[] serverPrivateKey = serverKeyPair.serverPrivateKey;
		assertNotNull(serverPrivateKey);
		assertEquals(32, serverPrivateKey.length);

		byte[] serverPublicKey = serverKeyPair.serverPublicKey;
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

		byte[] clientEnrollmentRecord = clientEnrollAccount.enrollmentRecord;
		assertNotNull(clientEnrollmentRecord);

		byte[] clientAccountKey = clientEnrollAccount.accountKey;
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

		byte[] serverPrivateKey = serverKeyPair.serverPrivateKey;
		assertNotNull(serverPrivateKey);

		byte[] serverPublicKey = serverKeyPair.serverPublicKey;
		assertNotNull(serverPublicKey);

		PheServerRotateKeysResult serverRotateKeys = this.server.rotateKeys(serverPrivateKey);
		assertNotNull(serverRotateKeys);

		byte[] serverRotatedPrivateKey = serverRotateKeys.newServerPrivateKey;
		assertNotNull(serverRotatedPrivateKey);
		assertEquals(32, serverRotatedPrivateKey.length);

		byte[] serverRotatedPublicKey = serverRotateKeys.newServerPublicKey;
		assertNotNull(serverRotatedPublicKey);
		assertEquals(65, serverRotatedPublicKey.length);

		byte[] serverUpdateToken = serverRotateKeys.updateToken;
		assertNotNull(serverUpdateToken);
		assertTrue(serverUpdateToken.length > 0);

		byte[] clientPrivateKey = this.client.generateClientPrivateKey();
		assertNotNull(clientPrivateKey);
		assertEquals(32, clientPrivateKey.length);

		this.client.setKeys(clientPrivateKey, serverRotatedPublicKey);

		PheClientRotateKeysResult clientRotateKeys = this.client.rotateKeys(serverUpdateToken);
		assertNotNull(clientRotateKeys);

		byte[] clientNewPrivateKey = clientRotateKeys.newClientPrivateKey;
		assertNotNull(clientNewPrivateKey);
		assertEquals(32, clientNewPrivateKey.length);

		byte[] serverNewPublicKey = clientRotateKeys.newServerPublicKey;
		assertNotNull(serverNewPublicKey);
		assertEquals(65, serverNewPublicKey.length);

		assertEquals(serverPublicKey.length, serverNewPublicKey.length);
		assertEquals(clientPrivateKey.length, clientNewPrivateKey.length);
	}

}
