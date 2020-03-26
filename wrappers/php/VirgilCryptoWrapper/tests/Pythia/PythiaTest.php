<?php
/**
 * Copyright (C) 2015-2019 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

namespace Virgil\CryptoWrapperTests\Pythia;

use Virgil\CryptoWrapper\Pythia\Pythia;

class PythiaTest extends \PHPUnit\Framework\TestCase
{
    private $pythia;

    private $kDeblindedPassword;

    private $kPassword;
    private $kTransformationKeyId;
    private $kTweak;
    private $kPythiaSecret;
    private $kNewPythiaSecret;
    private $kPythiaScopeSecret;
    private $kNewPythiaScopeSecret;

    protected function setUp(): void
    {
        $this->pythia = new Pythia();
        Pythia::configure();

        $this->kDeblindedPassword = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";

        $this->kPassword = "password";
        $this->kTransformationKeyId = "virgil.com";
        $this->kTweak = "alice";
        $this->kPythiaSecret = "master secret";
        $this->kNewPythiaSecret = "new master secret";
        $this->kPythiaScopeSecret = "server secret";
        $this->kNewPythiaScopeSecret = "new server secret";
    }

    protected function tearDown(): void
    {
        Pythia::cleanup();
        unset($this->pythia);
    }

    public function test_Pythia_blindDeblind_returnsSuccess()
    {
        try {
            list($blindedPassword, $blindingSecret) = Pythia::blind($this->kPassword);
            $this->assertNotNull($blindedPassword);
            $this->assertNotNull($blindingSecret);

            list($transformationPrivateKey, $transformationPublicKey) = Pythia::computeTransformationKeyPair
            ($this->kTransformationKeyId, $this->kPythiaSecret, $this->kPythiaScopeSecret);

            list($transformedPassword, $transformedTweak) = Pythia::transform($blindedPassword, $this->kTweak,
                $transformationPrivateKey);

            $deblind = Pythia::deblind($transformedPassword, $blindingSecret);
            $this->assertEquals($this->kDeblindedPassword, unpack("H*", $deblind)[1]);

        } catch (\Exception $e) {
            $this->fail($e->getMessage());
        }
    }

    public function test_Pythia_proveVerify_returnsSuccess()
    {
        try {
            list($blindedPassword, $blindingSecret) = Pythia::blind($this->kPassword);
            $this->assertNotNull($blindedPassword);
            $this->assertNotNull($blindingSecret);

            list($transformationPrivateKey, $transformationPublicKey) = Pythia::computeTransformationKeyPair
            ($this->kTransformationKeyId, $this->kPythiaSecret, $this->kPythiaScopeSecret);

            list($transformedPassword, $transformedTweak) = Pythia::transform($blindedPassword, $this->kTweak,
                $transformationPrivateKey);

            list($proofValueC, $proofValueU) = Pythia::prove($transformedPassword, $blindedPassword,
                $transformedTweak, $transformationPrivateKey, $transformationPublicKey);

            $isVerify = Pythia::verify($transformedPassword, $blindedPassword, $this->kTweak, $transformationPublicKey,
                $proofValueC, $proofValueU);

            $this->assertTrue($isVerify);

        } catch (\Exception $e) {
            $this->fail($e->getMessage());
        }
    }

    public function test_Pythia_updatePasswordToken_returnsSuccess()
    {
        try {
            list($blindedPassword, $blindingSecret) = Pythia::blind($this->kPassword);

            list($transformationPrivateKey, $transformationPublicKey) = Pythia::computeTransformationKeyPair
            ($this->kTransformationKeyId, $this->kPythiaSecret, $this->kPythiaScopeSecret);

            list($transformedPassword, $transformedTweak) = Pythia::transform($blindedPassword, $this->kTweak, $transformationPrivateKey);

            $deblind = Pythia::deblind($transformedPassword, $blindingSecret);

            list($newTransformationPrivateKey, $newTransformationPublicKey) = Pythia::computeTransformationKeyPair
            ($this->kTransformationKeyId, $this->kPythiaSecret, $this->kPythiaScopeSecret);

            $updateToken = Pythia::getPasswordUpdateToken($transformationPrivateKey, $newTransformationPrivateKey);

            $updatedDeblindPassword = Pythia::updateDeblindedWithToken($deblind, $updateToken);

            list($newTransformedPassword, $newTransformedTweak) = Pythia::transform($blindedPassword, $this->kTweak,
                $newTransformationPrivateKey);

            $newDeblind = Pythia::deblind($newTransformedPassword, $blindingSecret);

            $this->assertEquals($updatedDeblindPassword, $newDeblind);

            list($proofValueC, $proofValueU) = Pythia::prove($newTransformedPassword, $blindedPassword,
                $newTransformedTweak, $newTransformationPrivateKey, $newTransformationPublicKey);

            $isVerify = Pythia::verify($newTransformedPassword, $blindedPassword, $this->kTweak,
                $newTransformationPublicKey, $proofValueC, $proofValueU);

            $this->assertTrue($isVerify);

        } catch (\Exception $e) {
            $this->fail($e->getMessage());
        }
    }
}
