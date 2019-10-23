/**
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


const initFoundationError = (Module, modules) => {
    /**
     * Defines the library status codes.
     */
    class FoundationError extends Error {

        constructor(message) {
            super(message);
            this.name = 'FoundationError';
            this.message = message;
        }

        /**
         * Throw exception of this class with a message that corresponds to the given status code.
         */
        static handleStatusCode(statusCode) {
            if (statusCode == 0) {
                return;
            }

            if (statusCode == -1) {
                throw new FoundationError("This error should not be returned if assertions is enabled.");
            }

            if (statusCode == -2) {
                throw new FoundationError("Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.");
            }

            if (statusCode == -3) {
                throw new FoundationError("Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.");
            }

            if (statusCode == -101) {
                throw new FoundationError("Buffer capacity is not enough to hold result.");
            }

            if (statusCode == -200) {
                throw new FoundationError("Unsupported algorithm.");
            }

            if (statusCode == -201) {
                throw new FoundationError("Authentication failed during decryption.");
            }

            if (statusCode == -202) {
                throw new FoundationError("Attempt to read data out of buffer bounds.");
            }

            if (statusCode == -203) {
                throw new FoundationError("ASN.1 encoded data is corrupted.");
            }

            if (statusCode == -204) {
                throw new FoundationError("Attempt to read ASN.1 type that is bigger then requested C type.");
            }

            if (statusCode == -205) {
                throw new FoundationError("ASN.1 representation of PKCS#1 public key is corrupted.");
            }

            if (statusCode == -206) {
                throw new FoundationError("ASN.1 representation of PKCS#1 private key is corrupted.");
            }

            if (statusCode == -207) {
                throw new FoundationError("ASN.1 representation of PKCS#8 public key is corrupted.");
            }

            if (statusCode == -208) {
                throw new FoundationError("ASN.1 representation of PKCS#8 private key is corrupted.");
            }

            if (statusCode == -209) {
                throw new FoundationError("Encrypted data is corrupted.");
            }

            if (statusCode == -210) {
                throw new FoundationError("Underlying random operation returns error.");
            }

            if (statusCode == -211) {
                throw new FoundationError("Generation of the private or secret key failed.");
            }

            if (statusCode == -212) {
                throw new FoundationError("One of the entropy sources failed.");
            }

            if (statusCode == -213) {
                throw new FoundationError("Requested data to be generated is too big.");
            }

            if (statusCode == -214) {
                throw new FoundationError("Base64 encoded string contains invalid characters.");
            }

            if (statusCode == -215) {
                throw new FoundationError("PEM data is corrupted.");
            }

            if (statusCode == -216) {
                throw new FoundationError("Exchange key return zero.");
            }

            if (statusCode == -217) {
                throw new FoundationError("Ed25519 public key is corrupted.");
            }

            if (statusCode == -218) {
                throw new FoundationError("Ed25519 private key is corrupted.");
            }

            if (statusCode == -219) {
                throw new FoundationError("CURVE25519 public key is corrupted.");
            }

            if (statusCode == -220) {
                throw new FoundationError("CURVE25519 private key is corrupted.");
            }

            if (statusCode == -221) {
                throw new FoundationError("Elliptic curve public key format is corrupted see RFC 5480.");
            }

            if (statusCode == -222) {
                throw new FoundationError("Elliptic curve public key format is corrupted see RFC 5915.");
            }

            if (statusCode == -223) {
                throw new FoundationError("ASN.1 representation of a public key is corrupted.");
            }

            if (statusCode == -224) {
                throw new FoundationError("ASN.1 representation of a private key is corrupted.");
            }

            if (statusCode == -225) {
                throw new FoundationError("Key algorithm does not accept given type of public key.");
            }

            if (statusCode == -226) {
                throw new FoundationError("Key algorithm does not accept given type of private key.");
            }

            if (statusCode == -227) {
                throw new FoundationError("Post-quantum Falcon-Sign public key is corrupted.");
            }

            if (statusCode == -228) {
                throw new FoundationError("Post-quantum Falcon-Sign private key is corrupted.");
            }

            if (statusCode == -229) {
                throw new FoundationError("Generic Round5 library error.");
            }

            if (statusCode == -230) {
                throw new FoundationError("Post-quantum NIST Round5 public key is corrupted.");
            }

            if (statusCode == -231) {
                throw new FoundationError("Post-quantum NIST Round5 private key is corrupted.");
            }

            if (statusCode == -232) {
                throw new FoundationError("Compound public key is corrupted.");
            }

            if (statusCode == -233) {
                throw new FoundationError("Compound private key is corrupted.");
            }

            if (statusCode == -301) {
                throw new FoundationError("Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.");
            }

            if (statusCode == -302) {
                throw new FoundationError("Message Info is corrupted.");
            }

            if (statusCode == -303) {
                throw new FoundationError("Recipient defined with id is not found within message info during data decryption.");
            }

            if (statusCode == -304) {
                throw new FoundationError("Content encryption key can not be decrypted with a given private key.");
            }

            if (statusCode == -305) {
                throw new FoundationError("Content encryption key can not be decrypted with a given password.");
            }

            if (statusCode == -306) {
                throw new FoundationError("Custom parameter with a given key is not found within message info.");
            }

            if (statusCode == -307) {
                throw new FoundationError("A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.");
            }

            if (statusCode == -308) {
                throw new FoundationError("Signature format is corrupted.");
            }

            if (statusCode == -309) {
                throw new FoundationError("Message Info footer is corrupted.");
            }

            if (statusCode == -401) {
                throw new FoundationError("Brainkey password length is out of range.");
            }

            if (statusCode == -402) {
                throw new FoundationError("Brainkey number length should be 32 byte.");
            }

            if (statusCode == -403) {
                throw new FoundationError("Brainkey point length should be 65 bytes.");
            }

            if (statusCode == -404) {
                throw new FoundationError("Brainkey name is out of range.");
            }

            if (statusCode == -405) {
                throw new FoundationError("Brainkey internal error.");
            }

            if (statusCode == -406) {
                throw new FoundationError("Brainkey point is invalid.");
            }

            if (statusCode == -407) {
                throw new FoundationError("Brainkey number buffer length capacity should be >= 32 byte.");
            }

            if (statusCode == -408) {
                throw new FoundationError("Brainkey point buffer length capacity should be >= 32 byte.");
            }

            if (statusCode == -409) {
                throw new FoundationError("Brainkey seed buffer length capacity should be >= 32 byte.");
            }

            if (statusCode == -410) {
                throw new FoundationError("Brainkey identity secret is invalid.");
            }

            if (statusCode == -501) {
                throw new FoundationError("Invalid padding.");
            }

            if (statusCode == -601) {
                throw new FoundationError("Protobuf error.");
            }

            if (statusCode == -701) {
                throw new FoundationError("Session id doesnt match.");
            }

            if (statusCode == -702) {
                throw new FoundationError("Epoch not found.");
            }

            if (statusCode == -703) {
                throw new FoundationError("Wrong key type.");
            }

            if (statusCode == -704) {
                throw new FoundationError("Invalid signature.");
            }

            if (statusCode == -705) {
                throw new FoundationError("Ed25519 error.");
            }

            if (statusCode == -706) {
                throw new FoundationError("Duplicate epoch.");
            }

            if (statusCode == -707) {
                throw new FoundationError("Plain text too long.");
            }

            throw new FoundationError("Unexpected status code:" + statusCode);
        }
    }

    return FoundationError;
};

module.exports = initFoundationError;
