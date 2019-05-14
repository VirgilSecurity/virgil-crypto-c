package com.virgilsecurity.crypto.foundation;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(AndroidJUnit4.class)
public class Base64InstrumentedTest {

    @Test
    public void encode() {
        Random random = new CtrDrbg();
        ((CtrDrbg) random).setupDefaults();
        byte[] data = random.random(1000);
        byte[] expectedEncodedData = android.util.Base64.encode(data, android.util.Base64.NO_WRAP);

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
        byte[] encodedData = "2saYMwjfh6ZKmpzS8Gn71+Wl/DnURsjGIWcAAshaHnH32RDhpZSem6l5HhvLG0TZ5F7b1cDzB9Bk4XomxINviHozt3KZ3DmBKZitQAIU9/6/qCnJzuxbHgOteIFsE65WfOEmrVbK8sRZuVvp2MYbG/5FoCb6hTlHTgQHv5xafd0b8J/aAzGKm2r4Ug9kUQSwc1PgnzSazXh5z4Z1RYyMGPel/yv6ZfUWs5gDKRJAImuvzGL64fUCmxz9Fifua2G5t9DTpErTUIcuZgtuIqU9UoogJIxbkftxtGrBxzBMWveCIdsUNlqiT/ileOAofwiPn9V91Wybhk8gXSwIOV2B5YeZhNmzhZXK1JZKVIpvSIrNPuDJ11NdSCSJ0hpKSwuZdQZAIu6Mm3apgVFJBcEQNbc/Xh3PtTDx6asDqDktmywDj7E6xCUZZP9Z0A0pvsbzRSE9+X7y0V57sy8r8MKlVWlPGu5JJ4zLh+6BSthX6pshdvrNgLv/g0p3PgLsA47S5QWIb0L80sSQqePKyxvdWjsPepVlXaIOqgD2Db/9VHE4z51SquX/U5Lh5w4NeyEpRgBOvDKqgJVTY7HgjgL3zybzBwkxDWJjp7lx9X5gzKI4tEoV4LO3PuEl6h6TJ9BA+sDsCLhnrs0NkjyZURcju84R2a7cVn8GVTpW45wTom7/e+w41mdyTqUIEUyOgZ/GBbC4HYaUBXWShpyuih0VdQhYgn5WgDoKd4lpdpGe1MOiGiTVsr1q4eH84ajTus4j6YXYU7d2FmMsb+gDiWHtoKwmiXAqbShXbUSxwQE+dwv7T2Eaq4Vl+ZKzQe/617947FZHZylSbdLI8f6IMeVIxZxGx3eYTxQMHDB6cjugrmd0UCZ/4co3z2RPTHKVOAKfrXwGaxqhtuZgbp5a+a/SpRVfdnb2TjkWG7YqkfK4VXYS1MDvfwMnr5cIUwCyaicJ5wkNywKqzEmodaHEI94wGDZaH/ZJH5avIJrgcDsIs+/Ft483DwaJ9CxNOLWUZXTphLTSLbDuMy39P51lO0vl1s5jvnwgxjvCqnOo/8fw9/fvnASjHcDc9lSp1cGth6aS5mGwUKgwUxuKMHZk0/Py02tuTHSwCHQa77eXcWL50CsyMzXaEOoDkhoE9drg8yS7ccH4+LwG15q9sACufWoO66Bqy/I2P7NvCGB49KwVV7B/GECHRTSRk0/88N31KVT6XaHfhek/cDjp77ISCfwQE5acKqqJibzyW3dHhBZSd1Rce0XIbqmFKbZxhpJc9posuulG/3SPt9Q9UwbvAF+Tb9a7HK/+oG6PSh7GMiB/p/B263skKkKbmHGGA6UnFT0sxGmUAUU+uE7loa2sYQo+4Q==".getBytes(StandardCharsets.UTF_8);
        byte[] expectedDecodedData = android.util.Base64.decode(encodedData, android.util.Base64.DEFAULT);

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
