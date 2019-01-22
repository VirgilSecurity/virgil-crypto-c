// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    (1) Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
//    (2) Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
//    (3) Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

declare module '@virgilsecurity/phe' {
  type PrivateKey = Buffer;
  type PublicKey = Buffer;
  type EnrollmentResponse = Buffer;
  type EnrollmentRecord = Buffer;
  type AccountKey = Buffer;
  type VerifyPasswordRequest = Buffer;
  type VerifyPasswordResponse = Buffer;
  type UpdateToken = Buffer;
  type CipherText = Buffer;

  class Cipher {
    encrypt(plainText: Buffer, accountKey: AccountKey): CipherText;
    decrypt(cipherText: CipherText, accountKey: AccountKey): void;
  }

  class Client {
    setKeys(clientPrivateKey: PrivateKey, serverPublicKey: PublicKey): void;
    generateClientPrivateKey(): PrivateKey;
    enrollAccount(enrollmentResponse: EnrollmentResponse, password: Buffer): {
      enrollmentRecord: EnrollmentRecord;
      accountKey: AccountKey;
    };
    createVerifyPasswordRequest(
      enrollmentRecord: EnrollmentRecord,
      password: Buffer,
    ): VerifyPasswordRequest;
    checkResponseAndDecrypt(
      password: Buffer,
      enrollmentRecord: EnrollmentRecord,
      verifyPasswordResponse: VerifyPasswordResponse,
    ): AccountKey;
    rotateKeys(updateToken: UpdateToken): {
      newClientPrivateKey: PrivateKey;
      newServerPublicKey: PublicKey;
    };
    updateEnrollmentRecord(
      enrollmentRecord: EnrollmentRecord,
      updateToken: UpdateToken,
    ): EnrollmentRecord;
  }

  class Server {
    generateServerKeyPair(): { serverPrivateKey: PrivateKey, publicKey: PublicKey };
    getEnrollment(serverPrivateKey: PrivateKey, serverPublicKey: PublicKey): EnrollmentResponse;
    verifyPassword(
      serverPrivateKey: PrivateKey,
      serverPublicKey: PublicKey,
      verifyPasswordRequest: VerifyPasswordRequest,
    ): VerifyPasswordResponse;
    rotateKeys(serverPrivateKey: PrivateKey): {
      newServerPrivateKey: PrivateKey;
      newServerPublicKey: PublicKey;
      updateToken: UpdateToken;
    }
  }
}
