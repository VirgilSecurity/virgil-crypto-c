package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide post-quantum KEM based on ML-KEM-768 (mlkem-native).
* For algorithm details check https://github.com/pq-code-package/mlkem-native
*/
type MlKem struct {
    cCtx *C.vscf_ml_kem_t
}

func (obj *MlKem) SetRandom(random Random) {
    C.vscf_ml_kem_release_random(obj.cCtx)
    C.vscf_ml_kem_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *MlKem) SetupDefaults() error {
    proxyResult := C.vscf_ml_kem_setup_defaults(obj.cCtx)

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
func (obj *MlKem) GenerateKey() (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_generate_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult)
}

/* Handle underlying C context. */
func (obj *MlKem) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMlKem() *MlKem {
    ctx := C.vscf_ml_kem_new()
    obj := &MlKem {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MlKem).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMlKemWithCtx(ctx *C.vscf_ml_kem_t) *MlKem {
    obj := &MlKem {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MlKem).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMlKemCopy(ctx *C.vscf_ml_kem_t) *MlKem {
    obj := &MlKem {
        cCtx: C.vscf_ml_kem_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MlKem).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MlKem) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MlKem) delete() {
    C.vscf_ml_kem_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *MlKem) AlgId() AlgId {
    proxyResult := C.vscf_ml_kem_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *MlKem) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_ml_kem_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult)
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *MlKem) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := C.vscf_ml_kem_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *MlKem) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *MlKem) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *MlKem) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *MlKem) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *MlKem) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return FoundationImplementationWrapPrivateKey(proxyResult)
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
func (obj *MlKem) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPublicKey(proxyResult)
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (obj *MlKem) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return newRawPublicKeyWithCtx(proxyResult), nil
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
func (obj *MlKem) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    return FoundationImplementationWrapPrivateKey(proxyResult)
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (obj *MlKem) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_kem_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return newRawPrivateKeyWithCtx(proxyResult), nil
}

/*
* Return length in bytes required to hold encapsulated shared key.
*/
func (obj *MlKem) KemSharedKeyLen(key Key) uint {
    proxyResult := C.vscf_ml_kem_kem_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return uint(proxyResult)
}

/*
* Return length in bytes required to hold encapsulated key.
*/
func (obj *MlKem) KemEncapsulatedKeyLen(publicKey PublicKey) uint {
    proxyResult := C.vscf_ml_kem_kem_encapsulated_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult)
}

/*
* Generate a shared key and a key encapsulated message.
*/
func (obj *MlKem) KemEncapsulate(publicKey PublicKey) ([]byte, []byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.KemSharedKeyLen(publicKey.(Key))))
    if sharedKeyBufErr != nil {
        return nil, nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()

    encapsulatedKeyBuf, encapsulatedKeyBufErr := newBuffer(int(obj.KemEncapsulatedKeyLen(publicKey)))
    if encapsulatedKeyBufErr != nil {
        return nil, nil, encapsulatedKeyBufErr
    }
    defer encapsulatedKeyBuf.delete()


    proxyResult := C.vscf_ml_kem_kem_encapsulate(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), sharedKeyBuf.ctx, encapsulatedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return sharedKeyBuf.getData(), encapsulatedKeyBuf.getData(), nil
}

/*
* Decapsulate the shared key.
*/
func (obj *MlKem) KemDecapsulate(encapsulatedKey []byte, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := newBuffer(int(obj.KemSharedKeyLen(privateKey.(Key))))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.delete()
    encapsulatedKeyData := helperWrapData (encapsulatedKey)

    proxyResult := C.vscf_ml_kem_kem_decapsulate(obj.cCtx, encapsulatedKeyData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return sharedKeyBuf.getData(), nil
}
