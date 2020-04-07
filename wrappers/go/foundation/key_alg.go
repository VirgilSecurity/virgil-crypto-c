package foundation

import "C"

/*
* Common information about asymmetric key algorithm.
*/
type KeyAlg interface {

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
    * Import public key from the raw binary format.
    */
    ImportPublicKeyData (keyData []byte, keyAlgInfo AlgInfo) (PublicKey, error)

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    ExportPublicKey (publicKey PublicKey) (*RawPublicKey, error)

    /*
    * Return length in bytes required to hold exported public key.
    */
    ExportedPublicKeyDataLen (publicKey PublicKey) uint

    /*
    * Export public key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    ExportPublicKeyData (publicKey PublicKey) ([]byte, error)

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
    * Import private key from the raw binary format.
    */
    ImportPrivateKeyData (keyData []byte, keyAlgInfo AlgInfo) (PrivateKey, error)

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    ExportPrivateKey (privateKey PrivateKey) (*RawPrivateKey, error)

    /*
    * Return length in bytes required to hold exported private key.
    */
    ExportedPrivateKeyDataLen (privateKey PrivateKey) uint

    /*
    * Export private key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    ExportPrivateKeyData (privateKey PrivateKey) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

