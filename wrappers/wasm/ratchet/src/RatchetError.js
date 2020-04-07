/**
 * Copyright (C) 2015-2020 Virgil Security, Inc.
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


const initRatchetError = (Module, modules) => {
    /**
     * Defines the library status codes.
     */
    class RatchetError extends Error {

        constructor(message) {
            super(message);
            this.name = 'RatchetError';
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
                throw new RatchetError("Error during protobuf deserialization.");
            }

            if (statusCode == -2) {
                throw new RatchetError("Bad message type.");
            }

            if (statusCode == -3) {
                throw new RatchetError("AES error.");
            }

            if (statusCode == -4) {
                throw new RatchetError("RNG failed.");
            }

            if (statusCode == -5) {
                throw new RatchetError("Curve25519 error.");
            }

            if (statusCode == -6) {
                throw new RatchetError("Curve25519 error.");
            }

            if (statusCode == -7) {
                throw new RatchetError("Key deserialization failed.");
            }

            if (statusCode == -8) {
                throw new RatchetError("Invalid key type.");
            }

            if (statusCode == -9) {
                throw new RatchetError("Identity key doesn't match.");
            }

            if (statusCode == -10) {
                throw new RatchetError("Message already decrypted.");
            }

            if (statusCode == -11) {
                throw new RatchetError("Too many lost messages.");
            }

            if (statusCode == -12) {
                throw new RatchetError("Sender chain missing.");
            }

            if (statusCode == -13) {
                throw new RatchetError("Skipped message missing.");
            }

            if (statusCode == -14) {
                throw new RatchetError("Session is not initialized.");
            }

            if (statusCode == -15) {
                throw new RatchetError("Exceeded max plain text len.");
            }

            if (statusCode == -16) {
                throw new RatchetError("Too many messages for sender chain.");
            }

            if (statusCode == -17) {
                throw new RatchetError("Too many messages for receiver chain.");
            }

            if (statusCode == -18) {
                throw new RatchetError("Invalid padding.");
            }

            if (statusCode == -19) {
                throw new RatchetError("Too many participants.");
            }

            if (statusCode == -20) {
                throw new RatchetError("Too few participants.");
            }

            if (statusCode == -21) {
                throw new RatchetError("Sender not found.");
            }

            if (statusCode == -22) {
                throw new RatchetError("Cannot decrypt own messages.");
            }

            if (statusCode == -23) {
                throw new RatchetError("Invalid signature.");
            }

            if (statusCode == -24) {
                throw new RatchetError("Cannot remove myself.");
            }

            if (statusCode == -25) {
                throw new RatchetError("Epoch mismatch.");
            }

            if (statusCode == -26) {
                throw new RatchetError("Epoch not found.");
            }

            if (statusCode == -27) {
                throw new RatchetError("Session id mismatch.");
            }

            if (statusCode == -28) {
                throw new RatchetError("Simultaneous group user operation.");
            }

            if (statusCode == -29) {
                throw new RatchetError("Myself is included in info.");
            }

            if (statusCode == -30) {
                throw new RatchetError("Round5 error.");
            }

            if (statusCode == -31) {
                throw new RatchetError("Falcon error.");
            }

            if (statusCode == -32) {
                throw new RatchetError("Decaps signature is invalid.");
            }

            if (statusCode == -33) {
                throw new RatchetError("Error importing round5 key.");
            }

            throw new RatchetError("Unexpected status code:" + statusCode);
        }
    }

    return RatchetError;
};

module.exports = initRatchetError;
