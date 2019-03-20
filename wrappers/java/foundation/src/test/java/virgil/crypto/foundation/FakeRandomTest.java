package virgil.crypto.foundation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class FakeRandomTest extends SampleBasedTest {

	private FakeRandom random;

	@Before
	public void setup() {
		this.random = new FakeRandom();
	}

	@After
	public void teardown() {
		this.random.close();
	}

	@Test
	public void random() {
		byte[] bytes = this.random.random(10);

		assertNotNull(bytes);
		assertEquals(10, bytes.length);
	}

}
