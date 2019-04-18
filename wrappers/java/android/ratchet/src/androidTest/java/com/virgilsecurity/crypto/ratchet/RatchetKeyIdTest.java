package com.virgilsecurity.crypto.ratchet;

import android.support.test.runner.AndroidJUnit4;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RatchetKeyIdTest {

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
		byte[] publicKeyData = TestData.public_key_raw;
		byte[] expectedPublicKeyId = TestData.public_key_id;

		byte[] publicKeyId = this.ratchetKeyId.computePublicKeyId(publicKeyData);
		assertNotNull(publicKeyId);
		assertArrayEquals(expectedPublicKeyId, publicKeyId);
	}

}
