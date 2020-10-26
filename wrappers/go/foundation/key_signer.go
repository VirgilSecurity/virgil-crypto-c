package foundation

import "C"

/*
* Provide an interface for signing and verifying data digest
* with asymmetric keys.
*/
type KeySigner interface {

    context

    /*
    * Defines whether a public key can be imported or not.
    */
    GetCanImportPublicKey () bool

    /*
    * Define whether a public key can be exported or not.
    */
    GetCanExportPublicKey () bool

    /*
    * Define whether a private key can be imported or not.
    */
    GetCanImportPrivateKey () bool

    /*
    * Define whether a private key can be exported or not.
    */
    GetCanExportPrivateKey () bool

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    GenerateEphemeralKey (key Key) (PrivateKey, error)

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    ImportPublicKey (rawKey *RawPublicKey) (PublicKey, error)

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    ExportPublicKey (publicKey PublicKey) (*RawPublicKey, error)

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    ImportPrivateKey (rawKey *RawPrivateKey) (PrivateKey, error)

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    ExportPrivateKey (privateKey PrivateKey) (*RawPrivateKey, error)

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    CanSign (privateKey PrivateKey) bool

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    SignatureLen (privateKey PrivateKey) uint

    /*
    * Sign data digest with a given private key.
    */
    SignHash (privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error)

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    CanVerify (publicKey PublicKey) bool

    /*
    * Verify data digest with a given public key and signature.
    */
    VerifyHash (publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool
}

