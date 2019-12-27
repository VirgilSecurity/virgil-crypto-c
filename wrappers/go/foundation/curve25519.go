package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is implementation of Curve25519 elliptic curve algorithms.
*/
type Curve25519 struct {
    cCtx *C.vscf_curve25519_t /*ct10*/
}

func (obj *Curve25519) SetRandom(random Random) {
    C.vscf_curve25519_release_random(obj.cCtx)
    C.vscf_curve25519_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *Curve25519) SetEcies(ecies Ecies) {
    C.vscf_curve25519_release_ecies(obj.cCtx)
    C.vscf_curve25519_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(unsafe.Pointer(ecies.Ctx())))

    runtime.KeepAlive(ecies)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Curve25519) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_curve25519_setup_defaults(obj.cCtx)

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
func (obj *Curve25519) GenerateKey() (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_generate_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Curve25519) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCurve25519() *Curve25519 {
    ctx := C.vscf_curve25519_new()
    obj := &Curve25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Curve25519).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCurve25519WithCtx(ctx *C.vscf_curve25519_t /*ct10*/) *Curve25519 {
    obj := &Curve25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Curve25519).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCurve25519Copy(ctx *C.vscf_curve25519_t /*ct10*/) *Curve25519 {
    obj := &Curve25519 {
        cCtx: C.vscf_curve25519_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Curve25519).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Curve25519) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Curve25519) delete() {
    C.vscf_curve25519_delete(obj.cCtx)
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *Curve25519) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *Curve25519) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *Curve25519) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *Curve25519) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *Curve25519) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

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
func (obj *Curve25519) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *Curve25519) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

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
func (obj *Curve25519) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *Curve25519) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

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
func (obj *Curve25519) CanEncrypt(publicKey PublicKey, dataLen int) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Curve25519) EncryptedLen(publicKey PublicKey, dataLen int) int {
    proxyResult := /*pr4*/C.vscf_curve25519_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return int(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Curve25519) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), len(data)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_curve25519_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), dataData, outBuf.ctx)

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
func (obj *Curve25519) CanDecrypt(privateKey PrivateKey, dataLen int) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Curve25519) DecryptedLen(privateKey PrivateKey, dataLen int) int {
    proxyResult := /*pr4*/C.vscf_curve25519_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return int(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Curve25519) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), len(data)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_curve25519_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (obj *Curve25519) ComputeSharedKey(publicKey PublicKey, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := bufferNewBuffer(int(obj.SharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.Delete()


    proxyResult := /*pr4*/C.vscf_curve25519_compute_shared_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

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
func (obj *Curve25519) SharedKeyLen(key Key) int {
    proxyResult := /*pr4*/C.vscf_curve25519_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return int(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold encapsulated shared key.
*/
func (obj *Curve25519) KemSharedKeyLen(key Key) int {
    proxyResult := /*pr4*/C.vscf_curve25519_kem_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return int(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold encapsulated key.
*/
func (obj *Curve25519) KemEncapsulatedKeyLen(publicKey PublicKey) int {
    proxyResult := /*pr4*/C.vscf_curve25519_kem_encapsulated_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return int(proxyResult) /* r9 */
}

/*
* Generate a shared key and a key encapsulated message.
*/
func (obj *Curve25519) KemEncapsulate(publicKey PublicKey) ([]byte, []byte, error) {
    sharedKeyBuf, sharedKeyBufErr := bufferNewBuffer(int(obj.KemSharedKeyLen(publicKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.Delete()

    encapsulatedKeyBuf, encapsulatedKeyBufErr := bufferNewBuffer(int(obj.KemEncapsulatedKeyLen(publicKey.(PublicKey)) /* lg2 */))
    if encapsulatedKeyBufErr != nil {
        return nil, nil, encapsulatedKeyBufErr
    }
    defer encapsulatedKeyBuf.Delete()


    proxyResult := /*pr4*/C.vscf_curve25519_kem_encapsulate(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), sharedKeyBuf.ctx, encapsulatedKeyBuf.ctx)

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
func (obj *Curve25519) KemDecapsulate(encapsulatedKey []byte, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := bufferNewBuffer(int(obj.KemSharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.Delete()
    encapsulatedKeyData := helperWrapData (encapsulatedKey)

    proxyResult := /*pr4*/C.vscf_curve25519_kem_decapsulate(obj.cCtx, encapsulatedKeyData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return sharedKeyBuf.getData() /* r7 */, nil
}
