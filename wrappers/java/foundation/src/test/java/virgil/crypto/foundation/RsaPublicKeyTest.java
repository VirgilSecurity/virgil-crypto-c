package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
/*
public class RsaPublicKeyTest extends SampleBasedTest {

	private RsaPublicKey publicKey;

	@Before
	public void init() {
		this.publicKey = new RsaPublicKey();
	}

	@Test
	public void alg() {
		assertEquals(AlgId.RSA, this.publicKey.algId());
	}

	@Test
	public void keyLen() {
		assertEquals(getInt("key.rsa_public_key.key_len"), this.publicKey.keyLen());
	}

	@Test
	public void keyBitlen() {
		assertEquals(getInt("key.rsa_public_key.key_bitlen"), this.publicKey.keyBitlen());
	}

	@Test
	public void encrypt() {
		byte[] keyData = getBytes("encrypt.rsa_public_key.key");
		byte[] data = getBytes("encrypt.data");
		byte[] expectedEncryptedData = getBytes("encrypt.rsa_public_key.encrypted_data");

		this.publicKey.importPublicKey(keyData);

		byte[] encryptedData = this.publicKey.encrypt(data);

		assertNotNull(encryptedData);
		assertArrayEquals(expectedEncryptedData, encryptedData);
	}

	@Test
	public void encryptedLen() {
		int dataLen = getBytes("encrypt.data").length;
		int encryptedDataLen = getBytes("encrypt.rsa_public_key.encrypted_data").length;

		assertEquals(encryptedDataLen, this.publicKey.encryptedLen(dataLen));
	}

	@Test
	public void verify() {
		byte[] data = getBytes("verify.data");
		byte[] keyData = getBytes("verify.rsa_public_key.key");
		byte[] signature = getBytes("verify.rsa_public_key.signature");
		byte[] wrongSignature = getBytes("verify.rsa_public_key.wrong_signature");

		this.publicKey.importPublicKey(keyData);

		assertTrue(this.publicKey.verify(data, signature));
		assertFalse(this.publicKey.verify(data, wrongSignature));
	}

	@Test
	public void export_import() {
		RsaPrivateKey privateKey = new RsaPrivateKey();
		privateKey.generateKey();
		byte[] keyData = privateKey.extractPublicKey().exportPublicKey();

		this.publicKey.importPublicKey(keyData);

		// Export public key
		byte[] exportedKey = this.publicKey.exportPublicKey();
		assertNotNull(exportedKey);
		assertEquals(this.publicKey.exportedPublicKeyLen(), exportedKey.length);

		// Import public key
		RsaPublicKey importedPublicKey = new RsaPublicKey();
		importedPublicKey.importPublicKey(exportedKey);
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
*/