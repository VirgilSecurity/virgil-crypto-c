package com.virgilsecurity.crypto.pythia;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

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
		assertNotNull(blindResult.blindedPassword);
		assertNotNull(blindResult.blindingSecret);
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

		PythiaTransformResult transform = Pythia.transform(blindResult.blindedPassword, tweak,
				transformationKeyPair.transformationPrivateKey);
		assertNotNull(transform);

		byte[] deblindedPassword = Pythia.deblind(transform.transformedPassword, blindResult.blindingSecret);
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

		PythiaTransformResult transform = Pythia.transform(blindResult.blindedPassword, tweak,
				transformationKeyPair.transformationPrivateKey);
		assertNotNull(transform);

		PythiaProveResult prove = Pythia.prove(transform.transformedPassword, blindResult.blindedPassword,
				transform.transformedTweak, transformationKeyPair.transformationPrivateKey,
				transformationKeyPair.transformationPublicKey);

		Pythia.verify(transform.transformedPassword, blindResult.blindedPassword, tweak,
				transformationKeyPair.transformationPublicKey, prove.proofValueC, prove.proofValueU);
	}

}
