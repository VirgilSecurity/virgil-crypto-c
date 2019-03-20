package virgil.crypto.foundation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

public class Ed25519PublicKeyTest extends SampleBasedTest {

	private Ed25519PublicKey publicKey;

	@Before
	public void init() {
		this.publicKey = new Ed25519PublicKey();
	}

	@Test
	public void alg() {
		assertEquals(AlgId.ED25519, this.publicKey.algId());
	}

	@Test
	public void keyLen() {
		assertEquals(getInt("ed25519.key_len"), this.publicKey.keyLen());
	}

	@Test
	public void keyBitlen() {
		assertEquals(getInt("ed25519.key_bit_len"), this.publicKey.keyBitlen());
	}

	@Test
	public void verify() {
		byte[] data = getBytes("data");
		byte[] signature = getBytes("ed25519.signature");
		byte[] wrongSignature = getBytes("ed25519.wrong_signature");

		this.publicKey.importPublicKey(getBytes("ed25519.public_key"));

		assertTrue(this.publicKey.verifyHash(data, this.publicKey.algId(), signature));
		assertFalse(this.publicKey.verifyHash(data, this.publicKey.algId(), wrongSignature));
	}

	@Test
	public void export_import() {
		try (Ed25519PrivateKey privateKey = new Ed25519PrivateKey()) {
			privateKey.setupDefaults();
			privateKey.generateKey();
			byte[] keyData = privateKey.extractPublicKey().exportPublicKey();

			this.publicKey.importPublicKey(keyData);
		}

		// Export public key
		byte[] exportedKey = this.publicKey.exportPublicKey();
		assertNotNull(exportedKey);
		assertEquals(this.publicKey.exportedPublicKeyLen(), exportedKey.length);

		// Import public key
		try (Ed25519PublicKey importedPublicKey = new Ed25519PublicKey()) {
			importedPublicKey.importPublicKey(exportedKey);
		}
	}

	@Test
	public void getCanExportPublicKey() {
		assertTrue(this.publicKey.getCanExportPublicKey());
	}

	@Test
	public void getCanImportPublicKey() {
		assertTrue(this.publicKey.getCanImportPublicKey());
	}

}
