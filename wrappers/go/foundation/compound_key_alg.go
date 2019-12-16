package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implements public key cryptography over compound keys.
*
* Compound key contains 2 keys - one for encryption/decryption and
* one for signing/verifying.
*/
type CompoundKeyAlg struct {
    cCtx *C.vscf_compound_key_alg_t /*ct10*/
}

func (obj *CompoundKeyAlg) SetRandom(random Random) {
    C.vscf_compound_key_alg_release_random(obj.cCtx)
    C.vscf_compound_key_alg_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *CompoundKeyAlg) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Make compound private key from given.
*
* Note, this operation might be slow.
*/
func (obj *CompoundKeyAlg) MakeKey(cipherKey PrivateKey, signerKey PrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_make_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(cipherKey.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(signerKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(cipherKey)

    runtime.KeepAlive(signerKey)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *CompoundKeyAlg) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCompoundKeyAlg() *CompoundKeyAlg {
    ctx := C.vscf_compound_key_alg_new()
    obj := &CompoundKeyAlg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlg).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundKeyAlgWithCtx(ctx *C.vscf_compound_key_alg_t /*ct10*/) *CompoundKeyAlg {
    obj := &CompoundKeyAlg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlg).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundKeyAlgCopy(ctx *C.vscf_compound_key_alg_t /*ct10*/) *CompoundKeyAlg {
    obj := &CompoundKeyAlg {
        cCtx: C.vscf_compound_key_alg_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlg).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CompoundKeyAlg) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CompoundKeyAlg) delete() {
    C.vscf_compound_key_alg_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *CompoundKeyAlg) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *CompoundKeyAlg) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *CompoundKeyAlg) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *CompoundKeyAlg) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *CompoundKeyAlg) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *CompoundKeyAlg) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *CompoundKeyAlg) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *CompoundKeyAlg) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
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
func (obj *CompoundKeyAlg) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (obj *CompoundKeyAlg) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

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
func (obj *CompoundKeyAlg) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (obj *CompoundKeyAlg) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (obj *CompoundKeyAlg) CanEncrypt(publicKey PublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *CompoundKeyAlg) EncryptedLen(publicKey PublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *CompoundKeyAlg) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (obj *CompoundKeyAlg) CanDecrypt(privateKey PrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *CompoundKeyAlg) DecryptedLen(privateKey PrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *CompoundKeyAlg) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (obj *CompoundKeyAlg) CanSign(privateKey PrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_can_sign(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *CompoundKeyAlg) SignatureLen(privateKey PrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (obj *CompoundKeyAlg) SignHash(privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(obj.SignatureLen(privateKey.(PrivateKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.Delete()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_sign_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return signatureBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (obj *CompoundKeyAlg) CanVerify(publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_can_verify(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *CompoundKeyAlg) VerifyHash(publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_compound_key_alg_verify_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}
