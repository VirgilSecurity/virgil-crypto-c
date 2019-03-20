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
