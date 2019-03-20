package virgil.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

public class Base64Test extends SampleBasedTest {

	@Before
	public void setup() {
	}

	@Test
	public void encode() {
		byte[] data = getBytes("data");
		byte[] expectedEncodedData = getString("data").getBytes();

		byte[] encodedData = Base64.encode(data);

		assertNotNull(encodedData);
		assertArrayEquals(expectedEncodedData, encodedData);
	}

	@Test
	public void encodedLen() {
		assertEquals(0, Base64.encodedLen(0));
		assertEquals(5, Base64.encodedLen(1));
		assertEquals(9, Base64.encodedLen(4));
	}

	@Test
	public void decode() {
		byte[] expectedDecodedData = getBytes("data");
		byte[] encodedData = getString("data").getBytes();

		byte[] decodedData = Base64.decode(encodedData);

		assertNotNull(decodedData);
		assertArrayEquals(expectedDecodedData, decodedData);
	}

	@Test
	public void decodedLen() {
		assertEquals(0, Base64.decodedLen(0));
		assertEquals(4, Base64.decodedLen(1));
	}

}
