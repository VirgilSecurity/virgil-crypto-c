declare module '@virgilsecurity/phe' {
  type PrivateKey = Buffer;
  type PublicKey = Buffer;
  type EnrollmentResponse = Buffer;
  type EnrollmentRecord = Buffer;
  type AccountKey = Buffer;
  type VerifyPasswordRequest = Buffer;
  type VerifyPasswordResponse = Buffer;

  class Client {
    enrollAccount(
      clientPrivateKey: PrivateKey,
      serverPublicKey: PublicKey,
      enrollmentResponse: EnrollmentResponse,
      password: Buffer,
    ): { enrollmentRecord: EnrollmentRecord, accountKey: AccountKey };
    passwordVerifyRequest(
      clientPrivateKey: PrivateKey,
      serverPublicKey: PublicKey,
      enrollmentRecord: EnrollmentRecord,
      password: Buffer,
    ): VerifyPasswordRequest;
    verifyServerResponse(
      clientPrivateKey: PrivateKey,
      serverPublicKey: PublicKey,
      password: Buffer,
      enrollmentRecord: EnrollmentRecord,
      verifyPasswordResponse: VerifyPasswordResponse,
    ): AccountKey;
  }

  class Server {
    generateServerKeypair(): { privateKey: PrivateKey; publicKey: PublicKey };
    getEnrollment(privateKey: PrivateKey, publicKey: PublicKey): EnrollmentResponse;
    verifyPassword(
      privateKey: PrivateKey,
      publicKey: PublicKey,
      request: VerifyPasswordRequest,
    ): VerifyPasswordResponse;
  }
}
