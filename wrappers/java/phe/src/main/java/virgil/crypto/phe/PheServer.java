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

package virgil.crypto.phe;

import virgil.crypto.foundation.*;

/*
* Class for server-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREAD defined
*/
public class PheServer implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public PheServer() {
        super();
        this.cCtx = PheJNI.INSTANCE.pheServer_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public PheServer(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        PheJNI.INSTANCE.pheServer_close(this.cCtx);
    }

    /*
    * Random used for key generation, proofs, etc.
    */
    public void setRandom(Random random) {
        PheJNI.INSTANCE.pheServer_setRandom(this.cCtx, random);
    }

    /*
    * Random used for crypto operations to make them const-time
    */
    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.pheServer_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.pheServer_setupDefaults(this.cCtx);
    }

    /*
    * Generates new NIST P-256 server key pair for some client
    */
    public PheServerGenerateServerKeyPairResult generateServerKeyPair() throws PheException {
        return PheJNI.INSTANCE.pheServer_generateServerKeyPair(this.cCtx);
    }

    /*
    * Buffer size needed to fit EnrollmentResponse
    */
    public int enrollmentResponseLen() {
        return PheJNI.INSTANCE.pheServer_enrollmentResponseLen(this.cCtx);
    }

    /*
    * Generates a new random enrollment and proof for a new user
    */
    public byte[] getEnrollment(byte[] serverPrivateKey, byte[] serverPublicKey) throws PheException {
        return PheJNI.INSTANCE.pheServer_getEnrollment(this.cCtx, serverPrivateKey, serverPublicKey);
    }

    /*
    * Buffer size needed to fit VerifyPasswordResponse
    */
    public int verifyPasswordResponseLen() {
        return PheJNI.INSTANCE.pheServer_verifyPasswordResponseLen(this.cCtx);
    }

    /*
    * Verifies existing user's password and generates response with proof
    */
    public byte[] verifyPassword(byte[] serverPrivateKey, byte[] serverPublicKey, byte[] verifyPasswordRequest) throws PheException {
        return PheJNI.INSTANCE.pheServer_verifyPassword(this.cCtx, serverPrivateKey, serverPublicKey, verifyPasswordRequest);
    }

    /*
    * Buffer size needed to fit UpdateToken
    */
    public int updateTokenLen() {
        return PheJNI.INSTANCE.pheServer_updateTokenLen(this.cCtx);
    }

    /*
    * Updates server's private and public keys and issues an update token for use on client's side
    */
    public PheServerRotateKeysResult rotateKeys(byte[] serverPrivateKey) throws PheException {
        return PheJNI.INSTANCE.pheServer_rotateKeys(this.cCtx, serverPrivateKey);
    }
}

