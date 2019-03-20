package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Sha512Test extends SampleBasedTest {

	private Sha512 sha512;

	@Before
	public void init() {
		this.sha512 = new Sha512();
	}

	@Test
	public void algId() {
		AlgId algId = this.sha512.algId();
		assertNotNull(algId);
		assertEquals(AlgId.SHA512, algId);
	}

	@Test
	public void getDigestLen() {
		assertEquals(getInt("sha512.digest_len"), this.sha512.getDigestLen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("sha512.block_len"), this.sha512.getBlockLen());
	}

	@Test
	public void hash() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha512.hash");

		byte[] hash = this.sha512.hash(data);

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void hashStream() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha512.hash");

		this.sha512.start();

		int blockLen = this.sha512.getBlockLen();
		for (int startIndex = 0; startIndex < data.length; startIndex += blockLen) {
			byte[] block = ArrayUtils.subarray(data, startIndex, startIndex + blockLen);
			this.sha512.update(block);
		}

		byte[] hash = this.sha512.finish();

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

}
