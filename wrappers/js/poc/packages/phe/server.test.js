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

const { PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH } = require('./constants');
const { Client, Server } = require('./index');

describe('Server', () => {
  let server;

  beforeEach(() => {
    server = new Server();
  });

  it("should throw if invoked without 'new'", () => {
    const error = () => Server();
    expect(error).toThrow();
  });

  describe('generateServerKeyPair', () => {
    it('should return server private key and server public key', () => {
      const result = server.generateServerKeyPair();
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.serverPrivateKey)).toBeTruthy();
      expect(result.serverPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.serverPublicKey)).toBeTruthy();
      expect(result.serverPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
    });
  });

  describe('getEnrollment', () => {
    it('should return enrollment response', () => {
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      expect(Buffer.isBuffer(enrollmentResponse)).toBeTruthy();
    });
  });

  describe('verifyPassword', () => {
    it('should return verify password response', () => {
      const client = new Client();
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
      expect(Buffer.isBuffer(verifyPasswordResponse)).toBeTruthy();
    });
  });

  describe('rotateKeys', () => {
    it('should return new server private key, new server public key and update token', () => {
      const { serverPrivateKey } = server.generateServerKeyPair();
      const result = server.rotateKeys(serverPrivateKey);
      expect(Object.keys(result)).toHaveLength(3);
      expect(Buffer.isBuffer(result.newServerPrivateKey)).toBeTruthy();
      expect(result.newServerPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
      expect(result.newServerPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
      expect(Buffer.isBuffer(result.updateToken)).toBeTruthy();
    });
  });
});
