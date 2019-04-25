package com.virgilsecurity.crypto.ratchet;

import android.util.Base64;

public class TestData {
    public static final byte[] private_key = Base64.decode("MC4CAQAwBQYDK2VuBCIEIE4VNkJKhPPYPCYBPjwStxQOdp2HRApEpvUP7Q2EPTaS",
            Base64.NO_WRAP);

    public static final byte[] public_key = Base64.decode("MCowBQYDK2VuAyEAqaJunUCdIr9tcRt6EB0Avs+HapzHURQkBc/4S2kJczs=",
            Base64.NO_WRAP);

    public static final byte[] public_key_raw = Base64.decode("qaJunUCdIr9tcRt6EB0Avs+HapzHURQkBc/4S2kJczs=",
            Base64.NO_WRAP);

    public static final byte[] public_key_id = Base64.decode("5BBfhHC7reQ=",
            Base64.NO_WRAP);

}
