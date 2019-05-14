package com.virgilsecurity.crypto.foundation;

import static org.junit.Assert.assertNotNull;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang.ArrayUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RecipientCipherTest extends SampleBasedTest {

	private static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".getBytes(StandardCharsets.UTF_8);
	private static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID".getBytes(StandardCharsets.UTF_8);

	private RecipientCipher recipientCipher;

	@Before
	public void setup() {
		this.recipientCipher = new RecipientCipher();
	}

	@After
	public void tearDown() {
		this.recipientCipher.close();
	}

	@Test
	public void encrypt_decrypt__with_ed25519() {
		try (Ed25519PrivateKey privateKey = new Ed25519PrivateKey()) {
			privateKey.setupDefaults();
			privateKey.generateKey();

			Ed25519PublicKey publicKey = (Ed25519PublicKey) privateKey.extractPublicKey();
			byte[] recipientId = new byte[] { 0x01, 0x02, 0x03 };

			this.recipientCipher.addKeyRecipient(recipientId, publicKey);
			this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNER_ID, CUSTOM_PARAM_SIGNER_ID);
			this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNATURE, CUSTOM_PARAM_SIGNATURE);

			this.recipientCipher.startEncryption();

			byte[] processEncryptionData = this.recipientCipher.processEncryption(getBytes("data"));
			assertNotNull(processEncryptionData);

			byte[] finishEncryptionData = this.recipientCipher.finishEncryption();
			assertNotNull(finishEncryptionData);

			byte[] encryptedData = ArrayUtils.addAll(processEncryptionData, finishEncryptionData);

			this.recipientCipher.customParams().findData(CUSTOM_PARAM_SIGNER_ID);
			this.recipientCipher.customParams().findData(CUSTOM_PARAM_SIGNATURE);
		}
	}

}
