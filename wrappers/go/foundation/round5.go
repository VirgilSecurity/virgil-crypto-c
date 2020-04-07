package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide post-quantum encryption based on the round5 implementation.
* For algorithm details check https://github.com/round5/code
*/
type Round5 struct {
    cCtx *C.vscf_round5_t /*ct10*/
}

func (obj *Round5) SetRandom(random Random) {
    C.vscf_round5_release_random(obj.cCtx)
    C.vscf_round5_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Round5) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_round5_setup_defaults(obj.cCtx)

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
func (obj *Round5) GenerateKey(algId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_generate_key(obj.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Round5) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRound5() *Round5 {
    ctx := C.vscf_round5_new()
    obj := &Round5 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Round5).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRound5WithCtx(ctx *C.vscf_round5_t /*ct10*/) *Round5 {
    obj := &Round5 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Round5).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRound5Copy(ctx *C.vscf_round5_t /*ct10*/) *Round5 {
    obj := &Round5 {
        cCtx: C.vscf_round5_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Round5).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Round5) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Round5) delete() {
    C.vscf_round5_delete(obj.cCtx)
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *Round5) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *Round5) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *Round5) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *Round5) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *Round5) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

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
func (obj *Round5) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Import public key from the raw binary format.
*/
func (obj *Round5) ImportPublicKeyData(keyData []byte, keyAlgInfo AlgInfo) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_round5_import_public_key_data(obj.cCtx, keyDataData, (*C.vscf_impl_t)(unsafe.Pointer(keyAlgInfo.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(keyAlgInfo)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (obj *Round5) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return length in bytes required to hold exported public key.
*/
func (obj *Round5) ExportedPublicKeyDataLen(publicKey PublicKey) uint {
    proxyResult := /*pr4*/C.vscf_round5_exported_public_key_data_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Export public key to the raw binary format without algorithm information.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (obj *Round5) ExportPublicKeyData(publicKey PublicKey) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ExportedPublicKeyDataLen(publicKey.(PublicKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_round5_export_public_key_data(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return outBuf.getData() /* r7 */, nil
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
func (obj *Round5) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Import private key from the raw binary format.
*/
func (obj *Round5) ImportPrivateKeyData(keyData []byte, keyAlgInfo AlgInfo) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_round5_import_private_key_data(obj.cCtx, keyDataData, (*C.vscf_impl_t)(unsafe.Pointer(keyAlgInfo.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(keyAlgInfo)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (obj *Round5) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_round5_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return length in bytes required to hold exported private key.
*/
func (obj *Round5) ExportedPrivateKeyDataLen(privateKey PrivateKey) uint {
    proxyResult := /*pr4*/C.vscf_round5_exported_private_key_data_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Export private key to the raw binary format without algorithm information.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (obj *Round5) ExportPrivateKeyData(privateKey PrivateKey) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ExportedPrivateKeyDataLen(privateKey.(PrivateKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_round5_export_private_key_data(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return length in bytes required to hold encapsulated shared key.
*/
func (obj *Round5) KemSharedKeyLen(key Key) uint {
    proxyResult := /*pr4*/C.vscf_round5_kem_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return uint(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold encapsulated key.
*/
func (obj *Round5) KemEncapsulatedKeyLen(publicKey PublicKey) uint {
    proxyResult := /*pr4*/C.vscf_round5_kem_encapsulated_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Generate a shared key and a key encapsulated message.
*/
func (obj *Round5) KemEncapsulate(publicKey PublicKey) ([]byte, []byte, error) {
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


    proxyResult := /*pr4*/C.vscf_round5_kem_encapsulate(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), sharedKeyBuf.ctx, encapsulatedKeyBuf.ctx)

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
func (obj *Round5) KemDecapsulate(encapsulatedKey []byte, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.KemSharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()
    encapsulatedKeyData := helperWrapData (encapsulatedKey)

    proxyResult := /*pr4*/C.vscf_round5_kem_decapsulate(obj.cCtx, encapsulatedKeyData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return sharedKeyBuf.getData() /* r7 */, nil
}
