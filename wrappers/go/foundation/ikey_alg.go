package foundation

import "C"

/*
* Common information about asymmetric key algorithm.
*/
type IKeyAlg interface {

    IAlg

    /*
    * Defines whether a public key can be imported or not.
    */
    getCanImportPublicKey () bool

    /*
    * Define whether a public key can be exported or not.
    */
    getCanExportPublicKey () bool

    /*
    * Define whether a private key can be imported or not.
    */
    getCanImportPrivateKey () bool

    /*
    * Define whether a private key can be exported or not.
    */
    getCanExportPrivateKey () bool

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    GenerateEphemeralKey (key IKey) IPrivateKey

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
    ImportPublicKey (rawKey RawPublicKey) IPublicKey

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    ExportPublicKey (publicKey IPublicKey) RawPublicKey

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
    ImportPrivateKey (rawKey RawPrivateKey) IPrivateKey

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    ExportPrivateKey (privateKey IPrivateKey) RawPrivateKey
}

