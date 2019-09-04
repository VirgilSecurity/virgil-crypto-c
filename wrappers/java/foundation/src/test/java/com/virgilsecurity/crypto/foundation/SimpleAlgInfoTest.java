package com.virgilsecurity.crypto.foundation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class SimpleAlgInfoTest {

	private SimpleAlgInfo simpleAlgInfo;

	@Before
	public void setup() {
		this.simpleAlgInfo = new SimpleAlgInfo();
	}

	@After
	public void tearDown() {
		this.simpleAlgInfo.close();
	}

	@Test
	public void algId() {
		assertEquals(AlgId.NONE, this.simpleAlgInfo.algId());
	}

	@Test
	public void instantiate() {
		try (SimpleAlgInfo algInfo = new SimpleAlgInfo(AlgId.AES256_CBC)) {
			assertEquals(AlgId.AES256_CBC, algInfo.algId());
		}
	}

}
