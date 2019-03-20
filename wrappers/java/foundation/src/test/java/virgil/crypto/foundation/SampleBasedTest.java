package virgil.crypto.foundation;

import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.util.Base64;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class SampleBasedTest {

	private JsonObject sampleJson;

	public SampleBasedTest() {
		sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
				this.getClass().getClassLoader().getResourceAsStream("virgil/crypto/foundation/test_data.json")));
	}

	public String getString(String path) {
		return findJsonElement(path).getAsString();
	}

	public byte[] getBytes(String path) {
		return Base64.getDecoder().decode(findJsonElement(path).getAsString());
	}

	public int getInt(String path) {
		return findJsonElement(path).getAsInt();
	}

	private JsonElement findJsonElement(String path) {
		JsonObject jsonObject = this.sampleJson;
		String[] keys = path.split("\\.");
		int keyNum = 1;
		for (String key : keys) {
			if (keyNum++ < keys.length) {
				jsonObject = (JsonObject) jsonObject.get(key);
			} else {
				return jsonObject.get(key);
			}
		}
		fail(String.format("Path '%1$s' not found", path));
		return null;
	}
}
