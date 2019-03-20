package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Sha224Test extends SampleBasedTest {

	private Sha224 sha224;

	@Before
	public void init() {
		this.sha224 = new Sha224();
	}

	@Test
	public void algId() {
		AlgId algId = this.sha224.algId();
		assertNotNull(algId);
		assertEquals(AlgId.SHA224, algId);
	}

	@Test
	public void getDigestLen() {
		assertEquals(getInt("sha224.digest_len"), this.sha224.getDigestLen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("sha224.block_len"), this.sha224.getBlockLen());
	}

	@Test
	public void hash() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha224.hash");

		byte[] hash = this.sha224.hash(data);

		assertNotNull(hash);
		assertEquals(expectedHash.length, hash.length);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void hashStream() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha224.hash");

		this.sha224.start();

		int blockLen = this.sha224.getBlockLen();
		for (int startIndex = 0; startIndex < data.length; startIndex += blockLen) {
			byte[] block = ArrayUtils.subarray(data, startIndex, startIndex + blockLen);
			this.sha224.update(block);
		}

		byte[] hash = this.sha224.finish();

		assertNotNull(hash);
		assertEquals(expectedHash.length, hash.length);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void produceAlgInfo() {
		AlgInfo algInfo = this.sha224.produceAlgInfo();
		assertNotNull(algInfo);
		assertEquals(AlgId.SHA224, algInfo.algId());
	}

}
