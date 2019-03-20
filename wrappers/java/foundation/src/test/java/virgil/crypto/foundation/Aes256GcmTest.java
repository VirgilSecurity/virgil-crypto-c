package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Aes256GcmTest extends SampleBasedTest {

	private Aes256Gcm aes;

	@Before
	public void init() {
		this.aes = new Aes256Gcm();
	}

	@Test
	public void encrypt() {
		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));

		byte[] encryptedData = this.aes.encrypt(getBytes("data"));

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_gcm.encrypted_data"), encryptedData);
	}

	@Test
	public void encryptWithCipher() {
		byte[] data = getBytes("data");

		byte[] encryptedData = null;

		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));
		this.aes.startEncryption();

		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.update(data));
		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.finish());

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_gcm.encrypted_data"), encryptedData);
	}

	@Test
	public void decryptWithCipher() {
		byte[] encryptedData = getBytes("aes256_gcm.encrypted_data");
		byte[] decryptedData = null;

		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));
		this.aes.startDecryption();

		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.update(encryptedData));
		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.finish());

		assertNotNull(decryptedData);
		assertArrayEquals(getBytes("data"), decryptedData);
	}

	@Test
	public void decrypt() {
		byte[] expectedDecryptedData = getBytes("data");

		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));

		byte[] decryptedData = this.aes.decrypt(getBytes("aes256_gcm.encrypted_data"));

		assertNotNull(decryptedData);
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	public void getNonceLen() {
		assertEquals(getInt("aes256_gcm.nonce_len"), this.aes.getNonceLen());
	}

	@Test
	public void getKeyLen() {
		assertEquals(getInt("aes256_gcm.key_len"), this.aes.getKeyLen());
	}

	@Test
	public void getKeyBitlen() {
		assertEquals(getInt("aes256_gcm.key_bit_len"), this.aes.getKeyBitlen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("aes256_gcm.block_len"), this.aes.getBlockLen());
	}

	@Test
	public void getAuthTagLen() {
		assertEquals(getInt("aes256_gcm.auth_tag_len"), this.aes.getAuthTagLen());
	}

	@Test
	public void authEncrypt() {
		byte[] data = getBytes("data");
		byte[] authData = getBytes("aes256_gcm.auth_data");

		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));
		AuthEncryptAuthEncryptResult result = this.aes.authEncrypt(data, authData);

		assertNotNull(result);
		assertArrayEquals(getBytes("aes256_gcm.auth_out"), result.out);
		assertArrayEquals(getBytes("aes256_gcm.auth_tag"), result.tag);
	}

	@Test
	public void authDecrypt() {
		byte[] authData = getBytes("aes256_gcm.auth_data");
		byte[] out = getBytes("aes256_gcm.auth_out");
		byte[] tag = getBytes("aes256_gcm.auth_tag");

		this.aes.setKey(getBytes("aes256_gcm.key"));
		this.aes.setNonce(getBytes("aes256_gcm.nonce"));
		byte[] data = this.aes.authDecrypt(out, authData, tag);

		assertNotNull(data);
		assertArrayEquals(getBytes("data"), data);
	}

}
