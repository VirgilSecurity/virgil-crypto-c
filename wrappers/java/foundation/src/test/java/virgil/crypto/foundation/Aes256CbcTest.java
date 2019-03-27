package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Base64;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Aes256CbcTest extends SampleBasedTest {

	private Aes256Cbc aes;

	@Before
	public void init() {
		this.aes = new Aes256Cbc();
	}

	@Test
	public void encrypt() {
		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));

		byte[] encryptedData = this.aes.encrypt(getBytes("data"));

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_cbc.encrypted_data"), encryptedData);
	}

	@Test
	public void encryptWithCipher() {
		byte[] data = getBytes("data");

		byte[] encryptedData = null;

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));
		this.aes.startEncryption();

		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.update(data));
		encryptedData = ArrayUtils.addAll(encryptedData, this.aes.finish());

		assertNotNull(encryptedData);
		assertArrayEquals(getBytes("aes256_cbc.encrypted_data"), encryptedData);
	}

	@Test
	public void decryptWithCipher() {
		byte[] encryptedData = getBytes("aes256_cbc.encrypted_data");
		byte[] decryptedData = null;

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));
		this.aes.startDecryption();

		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.update(encryptedData));
		decryptedData = ArrayUtils.addAll(decryptedData, this.aes.finish());

		assertNotNull(decryptedData);
		assertArrayEquals(getBytes("data"), decryptedData);
	}

	@Test
	public void decrypt() {
		byte[] expectedDecryptedData = getBytes("data");

		this.aes.setKey(getBytes("aes256_cbc.key"));
		this.aes.setNonce(getBytes("aes256_cbc.iv"));

		byte[] decryptedData = this.aes.decrypt(getBytes("aes256_cbc.encrypted_data"));

		assertNotNull(decryptedData);
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	public void getNonceLen() {
		assertEquals(getInt("aes256_cbc.nonce_len"), this.aes.getNonceLen());
	}

	@Test
	public void getKeyLen() {
		assertEquals(getInt("aes256_cbc.key_len"), this.aes.getKeyLen());
	}

	@Test
	public void getKeyBitlen() {
		assertEquals(getInt("aes256_cbc.key_bit_len"), this.aes.getKeyBitlen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("aes256_cbc.block_len"), this.aes.getBlockLen());
	}

}
