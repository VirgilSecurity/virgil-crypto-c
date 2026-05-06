package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is implementation of Ed25519 elliptic curve algorithms.
*/
type Ed25519 struct {
    cCtx *C.vscf_ed25519_t /*ct10*/
}

func (obj *Ed25519) SetRandom(random Random) {
    C.vscf_ed25519_release_random(obj.cCtx)
    C.vscf_ed25519_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *Ed25519) SetEcies(ecies *Ecies) {
    C.vscf_ed25519_release_ecies(obj.cCtx)
    C.vscf_ed25519_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(unsafe.Pointer(ecies.Ctx())))

    runtime.KeepAlive(ecies)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Ed25519) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_ed25519_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Generate new private key.
* Note, this operation might be slow.
*/
func (obj *Ed25519) GenerateKey() (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_generate_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Ed25519) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEd25519() *Ed25519 {
    ctx := C.vscf_ed25519_new()
    obj := &Ed25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Ed25519).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519WithCtx(ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    obj := &Ed25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Ed25519).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519Copy(ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    obj := &Ed25519 {
        cCtx: C.vscf_ed25519_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Ed25519).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Ed25519) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Ed25519) delete() {
    C.vscf_ed25519_delete(obj.cCtx)
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *Ed25519) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *Ed25519) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *Ed25519) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *Ed25519) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *Ed25519) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

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
func (obj *Ed25519) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *Ed25519) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

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
func (obj *Ed25519) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *Ed25519) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

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
func (obj *Ed25519) CanEncrypt(publicKey PublicKey, dataLen uint) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Ed25519) EncryptedLen(publicKey PublicKey, dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Ed25519) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ed25519_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), dataData, outBuf.ctx)

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
func (obj *Ed25519) CanDecrypt(privateKey PrivateKey, dataLen uint) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Ed25519) DecryptedLen(privateKey PrivateKey, dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Ed25519) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ed25519_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), dataData, outBuf.ctx)

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
func (obj *Ed25519) CanSign(privateKey PrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_sign(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *Ed25519) SignatureLen(privateKey PrivateKey) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (obj *Ed25519) SignHash(privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := newBuffer(int(obj.SignatureLen(privateKey.(PrivateKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.delete()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_ed25519_sign_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

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
func (obj *Ed25519) CanVerify(publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_verify(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *Ed25519) VerifyHash(publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_ed25519_verify_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (obj *Ed25519) ComputeSharedKey(publicKey PublicKey, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.SharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()


    proxyResult := /*pr4*/C.vscf_ed25519_compute_shared_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    runtime.KeepAlive(privateKey)

    return sharedKeyBuf.getData() /* r7 */, nil
}

/*
* Return number of bytes required to hold shared key.
* Expect Public Key or Private Key.
*/
func (obj *Ed25519) SharedKeyLen(key Key) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return uint(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold encapsulated shared key.
*/
func (obj *Ed25519) KemSharedKeyLen(key Key) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_kem_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return uint(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold encapsulated key.
*/
func (obj *Ed25519) KemEncapsulatedKeyLen(publicKey PublicKey) uint {
    proxyResult := /*pr4*/C.vscf_ed25519_kem_encapsulated_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Generate a shared key and a key encapsulated message.
*/
func (obj *Ed25519) KemEncapsulate(publicKey PublicKey) ([]byte, []byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.KemSharedKeyLen(publicKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()

    encapsulatedKeyBuf, encapsulatedKeyBufErr := newBuffer(int(obj.KemEncapsulatedKeyLen(publicKey.(PublicKey)) /* lg2 */))
    if encapsulatedKeyBufErr != nil {
        return nil, nil, encapsulatedKeyBufErr
    }
    defer encapsulatedKeyBuf.delete()


    proxyResult := /*pr4*/C.vscf_ed25519_kem_encapsulate(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), sharedKeyBuf.ctx, encapsulatedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return sharedKeyBuf.getData() /* r7 */, encapsulatedKeyBuf.getData() /* r7 */, nil
}

/*
* Decapsulate the shared key.
*/
func (obj *Ed25519) KemDecapsulate(encapsulatedKey []byte, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.KemSharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()
    encapsulatedKeyData := helperWrapData (encapsulatedKey)

    proxyResult := /*pr4*/C.vscf_ed25519_kem_decapsulate(obj.cCtx, encapsulatedKeyData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return sharedKeyBuf.getData() /* r7 */, nil
}
