package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implements public key cryptography over hybrid keys.
* Hybrid encryption - TODO
* Hybrid signatures - TODO
*/
type HybridKeyAlg struct {
    cCtx *C.vscf_hybrid_key_alg_t /*ct10*/
}

func (obj *HybridKeyAlg) SetRandom(random Random) {
    C.vscf_hybrid_key_alg_release_random(obj.cCtx)
    C.vscf_hybrid_key_alg_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *HybridKeyAlg) SetCipher(cipher CipherAuth) {
    C.vscf_hybrid_key_alg_release_cipher(obj.cCtx)
    C.vscf_hybrid_key_alg_use_cipher(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(cipher.Ctx())))

    runtime.KeepAlive(cipher)
    runtime.KeepAlive(obj)
}

func (obj *HybridKeyAlg) SetHash(hash Hash) {
    C.vscf_hybrid_key_alg_release_hash(obj.cCtx)
    C.vscf_hybrid_key_alg_use_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))

    runtime.KeepAlive(hash)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *HybridKeyAlg) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Make hybrid private key from given keys.
*/
func (obj *HybridKeyAlg) MakeKey(firstKey PrivateKey, secondKey PrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_make_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(firstKey.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(secondKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(firstKey)

    runtime.KeepAlive(secondKey)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *HybridKeyAlg) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHybridKeyAlg() *HybridKeyAlg {
    ctx := C.vscf_hybrid_key_alg_new()
    obj := &HybridKeyAlg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlg).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridKeyAlgWithCtx(ctx *C.vscf_hybrid_key_alg_t /*ct10*/) *HybridKeyAlg {
    obj := &HybridKeyAlg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlg).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridKeyAlgCopy(ctx *C.vscf_hybrid_key_alg_t /*ct10*/) *HybridKeyAlg {
    obj := &HybridKeyAlg {
        cCtx: C.vscf_hybrid_key_alg_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlg).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HybridKeyAlg) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HybridKeyAlg) delete() {
    C.vscf_hybrid_key_alg_delete(obj.cCtx)
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *HybridKeyAlg) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *HybridKeyAlg) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *HybridKeyAlg) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *HybridKeyAlg) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *HybridKeyAlg) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

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
func (obj *HybridKeyAlg) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *HybridKeyAlg) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

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
func (obj *HybridKeyAlg) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *HybridKeyAlg) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

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
func (obj *HybridKeyAlg) CanEncrypt(publicKey PublicKey, dataLen uint) bool {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *HybridKeyAlg) EncryptedLen(publicKey PublicKey, dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *HybridKeyAlg) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), dataData, outBuf.ctx)

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
func (obj *HybridKeyAlg) CanDecrypt(privateKey PrivateKey, dataLen uint) bool {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *HybridKeyAlg) DecryptedLen(privateKey PrivateKey, dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *HybridKeyAlg) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), dataData, outBuf.ctx)

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
func (obj *HybridKeyAlg) CanSign(privateKey PrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_can_sign(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *HybridKeyAlg) SignatureLen(privateKey PrivateKey) uint {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (obj *HybridKeyAlg) SignHash(privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(obj.SignatureLen(privateKey.(PrivateKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.Delete()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_sign_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

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
func (obj *HybridKeyAlg) CanVerify(publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_can_verify(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *HybridKeyAlg) VerifyHash(publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_verify_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}
