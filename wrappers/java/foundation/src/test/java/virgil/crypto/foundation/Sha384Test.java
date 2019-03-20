package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Sha384Test extends SampleBasedTest {

	private Sha384 sha384;

	@Before
	public void init() {
		this.sha384 = new Sha384();
	}

	@Test
	public void algId() {
		AlgId algId = this.sha384.algId();
		assertNotNull(algId);
		assertEquals(AlgId.SHA384, algId);
	}

	@Test
	public void getDigestLen() {
		assertEquals(getInt("sha384.digest_len"), this.sha384.getDigestLen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("sha384.block_len"), this.sha384.getBlockLen());
	}

	@Test
	public void hash() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha384.hash");

		byte[] hash = this.sha384.hash(data);

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void hashStream() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha384.hash");

		this.sha384.start();

		int blockLen = this.sha384.getBlockLen();
		for (int startIndex = 0; startIndex < data.length; startIndex += blockLen) {
			byte[] block = ArrayUtils.subarray(data, startIndex, startIndex + blockLen);
			this.sha384.update(block);
		}

		byte[] hash = this.sha384.finish();

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

}
