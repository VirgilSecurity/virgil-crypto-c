/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

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
