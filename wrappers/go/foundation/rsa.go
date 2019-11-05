package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* RSA implementation.
*/
type Rsa struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IKeySigner
    cCtx *C.vscf_rsa_t /*ct10*/
}

func (this Rsa) SetRandom (random IRandom) {
    C.vscf_rsa_release_random(this.cCtx)
    C.vscf_rsa_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Rsa) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_rsa_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Generate new private key.
* Note, this operation might be slow.
*/
func (this Rsa) GenerateKey (bitlen uint32) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_generate_key(this.cCtx, (C.size_t)(bitlen)/*pa10*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this Rsa) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewRsa () *Rsa {
    ctx := C.vscf_rsa_new()
    return &Rsa {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaWithCtx (ctx *C.vscf_rsa_t /*ct10*/) *Rsa {
    return &Rsa {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaCopy (ctx *C.vscf_rsa_t /*ct10*/) *Rsa {
    return &Rsa {
        cCtx: C.vscf_rsa_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Rsa) clear () {
    C.vscf_rsa_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Rsa) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Rsa) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Rsa) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_rsa_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func (this Rsa) GetCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (this Rsa) GetCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (this Rsa) GetCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (this Rsa) GetCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (this Rsa) GenerateEphemeralKey (key IKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_generate_ephemeral_key(this.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

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
func (this Rsa) ImportPublicKey (rawKey *RawPublicKey) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_import_public_key(this.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (this Rsa) ExportPublicKey (publicKey IPublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_export_public_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

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
func (this Rsa) ImportPrivateKey (rawKey *RawPrivateKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_import_private_key(this.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (this Rsa) ExportPrivateKey (privateKey IPrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_export_private_key(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (this Rsa) CanEncrypt (publicKey IPublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Rsa) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_encrypted_len(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (this Rsa) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(this.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.clear()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_rsa_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (this Rsa) CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Rsa) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_decrypted_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (this Rsa) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(this.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.clear()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_rsa_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (this Rsa) CanSign (privateKey IPrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_sign(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (this Rsa) SignatureLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_signature_len(this.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (this Rsa) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(this.SignatureLen(privateKey.(IKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.clear()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_rsa_sign_hash(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (this Rsa) CanVerify (publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_verify(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (this Rsa) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_rsa_verify_hash(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    return bool(proxyResult) /* r9 */
}
