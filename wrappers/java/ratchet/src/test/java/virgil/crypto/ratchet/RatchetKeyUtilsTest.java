package virgil.crypto.ratchet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import virgil.crypto.foundation.Curve25519PrivateKey;
import virgil.crypto.foundation.FoundationException;

public class RatchetKeyUtilsTest extends SampleBasedTest {

	private RatchetKeyUtils keyUtils;

	@Before
	public void setup() {
		this.keyUtils = new RatchetKeyUtils();
	}

	@After
	public void tearDown() {
		this.keyUtils.close();
	}

	@Test
	@Ignore
	public void extractCurveKeys() {
		byte[] privateKeyData = getBytes("curve.private_key");
		byte[] publicKeyData = getBytes("curve.public_key");

		byte[] privateKeyRaw = this.keyUtils.extractRatchetPrivateKey(privateKeyData, false, true, false);
		assertNotNull(privateKeyRaw);

		byte[] publicKeyRaw = this.keyUtils.extractRatchetPublicKey(publicKeyData, false, true, false);
		assertNotNull(publicKeyRaw);

		try (Curve25519PrivateKey privateKey = new Curve25519PrivateKey()) {
			privateKey.importPrivateKey(privateKeyRaw);

			byte[] extractedPublicKey = privateKey.extractPublicKey().exportPublicKey();
			assertArrayEquals(extractedPublicKey, publicKeyRaw);
		} catch (FoundationException e) {
			fail("Error code: " + e.getStatusCode());
		}
	}

	@Test
	@Ignore
	public void extractEdKeys() {
		byte[] privateKeyData = getBytes("ed.private_key");
		byte[] publicKeyData = getBytes("ed.public_key");

		byte[] privateKeyRaw = this.keyUtils.extractRatchetPrivateKey(privateKeyData, true, false, false);
		assertNotNull(privateKeyRaw);

		byte[] publicKeyRaw = this.keyUtils.extractRatchetPublicKey(publicKeyData, true, false, false);
		assertNotNull(publicKeyRaw);

		try (Curve25519PrivateKey privateKey = new Curve25519PrivateKey()) {
			privateKey.importPrivateKey(privateKeyRaw);

			byte[] extractedPublicKey = privateKey.extractPublicKey().exportPublicKey();
			assertArrayEquals(extractedPublicKey, publicKeyRaw);
		} catch (FoundationException e) {
			fail("Error code: " + e.getStatusCode());
		}

	}

	@Test
	public void computePublicKeyId() {
		byte[] publicKeyData = getBytes("curve.public_key_raw");
		byte[] expectedPublicKeyId = getBytes("curve.public_key_id");

		byte[] publicKeyId = this.keyUtils.computePublicKeyId(publicKeyData, false);
		assertNotNull(publicKeyId);
		assertArrayEquals(expectedPublicKeyId, publicKeyId);
	}

}
