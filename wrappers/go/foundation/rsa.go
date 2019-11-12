package foundation

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

func (obj *Rsa) SetRandom (random IRandom) {
    C.vscf_rsa_release_random(obj.cCtx)
    C.vscf_rsa_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Rsa) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_rsa_setup_defaults(obj.cCtx)

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
func (obj *Rsa) GenerateKey (bitlen uint32) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_generate_key(obj.cCtx, (C.size_t)(bitlen)/*pa10*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Rsa) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *Rsa) Delete () {
    C.vscf_rsa_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Rsa) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Rsa) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Rsa) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_rsa_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *Rsa) GetCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *Rsa) GetCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *Rsa) GetCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *Rsa) GetCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *Rsa) GenerateEphemeralKey (key IKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

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
func (obj *Rsa) ImportPublicKey (rawKey *RawPublicKey) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

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
func (obj *Rsa) ExportPublicKey (publicKey IPublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_export_public_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

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
func (obj *Rsa) ImportPrivateKey (rawKey *RawPrivateKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

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
func (obj *Rsa) ExportPrivateKey (privateKey IPrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_rsa_export_private_key(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (obj *Rsa) CanEncrypt (publicKey IPublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Rsa) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Rsa) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_rsa_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf.ctx)

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
func (obj *Rsa) CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Rsa) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Rsa) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_rsa_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (obj *Rsa) CanSign (privateKey IPrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_sign(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *Rsa) SignatureLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_signature_len(obj.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (obj *Rsa) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(obj.SignatureLen(privateKey.(IKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.Delete()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_rsa_sign_hash(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (obj *Rsa) CanVerify (publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_rsa_can_verify(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *Rsa) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_rsa_verify_hash(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    return bool(proxyResult) /* r9 */
}
