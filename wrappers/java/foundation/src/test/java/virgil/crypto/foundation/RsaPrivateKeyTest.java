package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class RsaPrivateKeyTest extends SampleBasedTest {

	private RsaPrivateKey rsaPrivateKey;

	@Before
	public void init() {
		this.rsaPrivateKey = new RsaPrivateKey();
	}

	@Test
	public void algId() {
		assertEquals(AlgId.RSA, this.rsaPrivateKey.algId());
	}

	@Test
	public void keyLen() {
		// Key is no generated yet
		assertEquals(0, this.rsaPrivateKey.keyLen());
	}

	@Test
	public void keyBitlen() {
		assertEquals(0, this.rsaPrivateKey.keyBitlen());
	}

	@Test
	public void generateKey() {
		this.rsaPrivateKey.setupDefaults();
		this.rsaPrivateKey.generateKey();
//		assertEquals(getInt("rsa.key_len"), this.rsaPrivateKey.keyLen());
	}

	@Test
	@Ignore
	public void decrypt() {
		byte[] key = getBytes("decrypt.rsa_private_key.key");
		byte[] encryptedData = getBytes("decrypt.rsa_private_key.encrypted_data");
		byte[] expectedDecryptedData = getBytes("encrypt.data");

		this.rsaPrivateKey.importPrivateKey(key);

		byte[] decryptedData = this.rsaPrivateKey.decrypt(encryptedData);

		assertNotNull(decryptedData);
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	@Ignore
	public void decryptedLen() {
		int encryptedData = getBytes("decrypt.rsa_private_key.encrypted_data").length;
		int decryptedDataLen = getBytes("encrypt.data").length;

		assertEquals(decryptedDataLen, this.rsaPrivateKey.decryptedLen(encryptedData));
	}
	/*
	 * @Test public void sign() { byte[] data = getBytes("sign.data"); byte[] key =
	 * getBytes("sign.rsa_private_key.key"); byte[] expectedSignature =
	 * getBytes("sign.rsa_private_key.signature");
	 * 
	 * this.rsaPrivateKey.importPrivateKey(key);
	 * 
	 * byte[] signature = this.rsaPrivateKey.sign(data);
	 * 
	 * assertNotNull(signature); assertArrayEquals(expectedSignature, signature); }
	 * 
	 * @Test public void signatureLen() {
	 * assertEquals(getBytes("sign.rsa_private_key.signature").length,
	 * this.rsaPrivateKey.signatureLen()); }
	 * 
	 * @Test public void export_import() { this.rsaPrivateKey.generateKey();
	 * 
	 * // Export private key byte[] exportedKey =
	 * this.rsaPrivateKey.exportPrivateKey(); assertNotNull(exportedKey);
	 * assertEquals(this.rsaPrivateKey.exportedPrivateKeyLen(), exportedKey.length);
	 * 
	 * // Import private key RsaPrivateKey importedPrivateKey = new RsaPrivateKey();
	 * importedPrivateKey.importPrivateKey(exportedKey);
	 * 
	 * // Sing the same data with imported byte[] data = getBytes("sign.data");
	 * byte[] signWithGeneratedKey = this.rsaPrivateKey.sign(data); byte[]
	 * signWithImportedKey = importedPrivateKey.sign(data);
	 * 
	 * assertArrayEquals(signWithGeneratedKey, signWithImportedKey); }
	 * 
	 * @Test public void getCanExportPrivateKey() {
	 * assertTrue(this.rsaPrivateKey.getCanExportPrivateKey()); }
	 * 
	 * @Test public void getCanImportPrivateKey() {
	 * assertTrue(this.rsaPrivateKey.getCanImportPrivateKey()); }
	 * 
	 * @Test public void extractPublicKey() { RsaPublicKey publicKey =
	 * (RsaPublicKey) this.rsaPrivateKey.extractPublicKey();
	 * 
	 * assertNotNull(publicKey);
	 * 
	 * byte[] data = getBytes("sign.data"); byte[] signature =
	 * this.rsaPrivateKey.sign(data);
	 * 
	 * assertTrue(publicKey.verify(data, signature)); }
	 */
}