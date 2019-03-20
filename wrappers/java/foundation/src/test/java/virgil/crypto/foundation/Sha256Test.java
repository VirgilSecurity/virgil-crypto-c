package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class Sha256Test extends SampleBasedTest {

	private Sha256 sha256;

	@Before
	public void init() {
		this.sha256 = new Sha256();
	}

	@Test
	public void produceAlgInfo() {
		AlgInfo algInfo = this.sha256.produceAlgInfo();
		assertNotNull(algInfo);
		assertEquals(AlgId.SHA256, algInfo.algId());
	}

	@Test
	public void algId() {
		AlgId algId = this.sha256.algId();
		assertNotNull(algId);
		assertEquals(AlgId.SHA256, algId);
	}

	@Test
	public void getDigestLen() {
		assertEquals(getInt("sha256.digest_len"), this.sha256.getDigestLen());
	}

	@Test
	public void getBlockLen() {
		assertEquals(getInt("sha256.block_len"), this.sha256.getBlockLen());
	}

	@Test
	public void hash() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha256.hash");

		byte[] hash = this.sha256.hash(data);

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

	@Test
	public void hashStream() {
		byte[] data = getBytes("data");
		byte[] expectedHash = getBytes("sha256.hash");

		this.sha256.start();

		int blockLen = this.sha256.getBlockLen();
		for (int startIndex = 0; startIndex < data.length; startIndex += blockLen) {
			byte[] block = ArrayUtils.subarray(data, startIndex, startIndex + blockLen);
			this.sha256.update(block);
		}

		byte[] hash = this.sha256.finish();

		assertNotNull(hash);
		assertArrayEquals(expectedHash, hash);
	}

}
