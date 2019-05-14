package com.virgilsecurity.crypto.pythia;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PythiaTest extends SampleBasedTest {

	@Before
	public void setup() {
		Pythia.configure();
	}

	@After
	public void tearDown() {
		Pythia.cleanup();
	}

	@Test
	public void blind() {
		byte[] password = getStringAsBytes("password");

		PythiaBlindResult blindResult = Pythia.blind(password);
		assertNotNull(blindResult);
		assertNotNull(blindResult.getBlindedPassword());
		assertNotNull(blindResult.getBlindingSecret());
	}

	@Test
	public void blindEvalDeblind() {
		byte[] transformationKeyId = getStringAsBytes("w");
		byte[] tweak = getStringAsBytes("t");
		byte[] pythiaSecret = getStringAsBytes("msk");
		byte[] pythiaScopeSecret = getStringAsBytes("ssk");
		byte[] password = getStringAsBytes("password");

		PythiaBlindResult blindResult = Pythia.blind(password);
		assertNotNull(blindResult);

		PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
				.computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
		assertNotNull(transformationKeyPair);

		PythiaTransformResult transform = Pythia.transform(blindResult.getBlindedPassword(), tweak,
				transformationKeyPair.getTransformationPrivateKey());
		assertNotNull(transform);

		byte[] deblindedPassword = Pythia.deblind(transform.getTransformedPassword(), blindResult.getBlindingSecret());
		assertNotNull(deblindedPassword);

		assertArrayEquals(getBytes("deblinded_password"), deblindedPassword);
	}

	@Test
	public void blindEvalProveVerify() {
		byte[] transformationKeyId = getStringAsBytes("w");
		byte[] tweak = getStringAsBytes("t");
		byte[] pythiaSecret = getStringAsBytes("msk");
		byte[] pythiaScopeSecret = getStringAsBytes("ssk");
		byte[] password = getStringAsBytes("password");

		PythiaBlindResult blindResult = Pythia.blind(password);
		assertNotNull(blindResult);

		PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
				.computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
		assertNotNull(transformationKeyPair);

		PythiaTransformResult transform = Pythia.transform(blindResult.getBlindedPassword(), tweak,
				transformationKeyPair.getTransformationPrivateKey());
		assertNotNull(transform);

		PythiaProveResult prove = Pythia.prove(transform.getTransformedPassword(), blindResult.getBlindedPassword(),
				transform.getTransformedTweak(), transformationKeyPair.getTransformationPrivateKey(),
				transformationKeyPair.getTransformationPublicKey());

		assertTrue(Pythia.verify(transform.getTransformedPassword(), blindResult.getBlindedPassword(), tweak,
				transformationKeyPair.getTransformationPublicKey(), prove.getProofValueC(), prove.getProofValueU()));
	}

}
