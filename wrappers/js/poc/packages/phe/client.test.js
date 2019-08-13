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

/* eslint-env jest */

const { PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, ACCOUNT_KEY_LENGTH } = require('./constants');
const { Client, Server } = require('./index');

describe('Client', () => {
  let client;
  let server;

  beforeEach(() => {
    client = new Client();
    server = new Server();
  });

  it("should throw if invoked without 'new'", () => {
    const error = () => Client();
    expect(error).toThrow();
  });

  describe('setKeys', () => {
    it('should work', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPublicKey } = server.generateServerKeyPair();
      const result = client.setKeys(clientPrivateKey, serverPublicKey);
      expect(result).toBeUndefined();
    });
  });

  describe('generateClientPrivateKey', () => {
    it('should return client private key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      expect(Buffer.isBuffer(clientPrivateKey)).toBeTruthy();
      expect(clientPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
    });
  });

  describe('enrollAccount', () => {
    it('should return enrollment record and account key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const result = client.enrollAccount(enrollmentResponse, password);
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.enrollmentRecord)).toBeTruthy();
      expect(Buffer.isBuffer(result.accountKey)).toBeTruthy();
    });
  });

  describe('createVerifyPasswordRequest', () => {
    it('should return verify password request', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const verifyPasswordRequest = client.createVerifyPasswordRequest(enrollmentRecord, password);
      expect(Buffer.isBuffer(verifyPasswordRequest)).toBeTruthy();
    });
  });

  describe('checkResponseAndDecrypt', () => {
    it('should return account key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const verifyPasswordRequest = client.createVerifyPasswordRequest(enrollmentRecord, password);
      const verifyPasswordResponse = server.verifyPassword(
        serverPrivateKey,
        serverPublicKey,
        verifyPasswordRequest,
      );
      const accountKey = client.checkResponseAndDecrypt(
        password,
        enrollmentRecord,
        verifyPasswordResponse,
      );
      expect(Buffer.isBuffer(accountKey)).toBeTruthy();
      expect(accountKey).toHaveLength(ACCOUNT_KEY_LENGTH);
    });
  });

  describe('rotateKeys', () => {
    it('should return new client private key and new server public key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const { updateToken } = server.rotateKeys(serverPrivateKey);
      const result = client.rotateKeys(updateToken);
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.newClientPrivateKey)).toBeTruthy();
      expect(result.newClientPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
      expect(result.newServerPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
    });
  });

  describe('updateEnrollmentRecord', () => {
    it('should return updated enrollment record', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const { updateToken } = server.rotateKeys(serverPrivateKey);
      const updatedEnrollmentRecord = client.updateEnrollmentRecord(enrollmentRecord, updateToken);
      expect(Buffer.isBuffer(updatedEnrollmentRecord)).toBeTruthy();
    });
  });
});
