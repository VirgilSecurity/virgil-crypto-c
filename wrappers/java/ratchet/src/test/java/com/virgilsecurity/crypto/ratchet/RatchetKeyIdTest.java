package com.virgilsecurity.crypto.ratchet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RatchetKeyIdTest extends SampleBasedTest {

	private RatchetKeyId ratchetKeyId;

	@Before
	public void setup() {
		this.ratchetKeyId = new RatchetKeyId();
	}

	@After
	public void tearDown() {
		this.ratchetKeyId.close();
	}

	@Test
	public void computePublicKeyId() {
		byte[] publicKeyData = getBytes("curve.public_key_raw");
		byte[] expectedPublicKeyId = getBytes("curve.public_key_id");

		byte[] publicKeyId = this.ratchetKeyId.computePublicKeyId(publicKeyData);
		assertNotNull(publicKeyId);
		assertArrayEquals(expectedPublicKeyId, publicKeyId);
	}

}
