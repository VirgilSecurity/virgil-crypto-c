package virgil.crypto.phe;

import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class PheCipherInstrumentedTest {

    private PheCipher cipher;

    @Before
    public void setup() {
        this.cipher = new PheCipher();
    }

    @After
    public void teardown() {
        this.cipher.close();
    }

    @Test
    public void testFullFlowShouldSucceed() throws PheException {
        byte[] plainText = "plain text".getBytes(StandardCharsets.UTF_8);
        byte[] accountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC".getBytes(StandardCharsets.UTF_8); // 32 bytes string

        assertEquals(32, accountKey.length);

        this.cipher.setupDefaults();

        byte[] encryptedData = this.cipher.encrypt(plainText, accountKey);
        byte[] decryptedData = this.cipher.decrypt(encryptedData, accountKey);

        assertArrayEquals(plainText, decryptedData);
    }

    @Test
    public void testFullFlowWrongKeyShouldFail() throws PheException {
        byte[] plainText = "plain text".getBytes(StandardCharsets.UTF_8);
        byte[] accountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC".getBytes(StandardCharsets.UTF_8);
        byte[] wrongAccountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjD".getBytes(StandardCharsets.UTF_8);

        this.cipher.setupDefaults();
        byte[] encryptedData = this.cipher.encrypt(plainText, accountKey);
        try {
            this.cipher.decrypt(encryptedData, wrongAccountKey);
            fail();
        } catch (PheException e) {
            assertEquals(PheException.ERROR_AES_FAILED, e.getStatusCode());
        }
    }
}
