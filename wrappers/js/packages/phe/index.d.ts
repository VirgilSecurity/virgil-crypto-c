declare module '@virgilsecurity/phe' {
  type PrivateKey = Buffer;
  type PublicKey = Buffer;
  type EnrollmentResponse = Buffer;
  type EnrollmentRecord = Buffer;
  type AccountKey = Buffer;
  type VerifyPasswordRequest = Buffer;
  type VerifyPasswordResponse = Buffer;
  type UpdateToken = Buffer;

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
