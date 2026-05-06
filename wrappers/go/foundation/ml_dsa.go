package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide post-quantum signature based on ML-DSA-65 (mldsa-native).
* For algorithm details check https://github.com/pq-code-package/mldsa-native
*/
type MlDsa struct {
    cCtx *C.vscf_ml_dsa_t
}

func (obj *MlDsa) SetRandom(random Random) {
    C.vscf_ml_dsa_release_random(obj.cCtx)
    C.vscf_ml_dsa_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *MlDsa) SetupDefaults() error {
    proxyResult := C.vscf_ml_dsa_setup_defaults(obj.cCtx)

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
func (obj *MlDsa) GenerateKey() (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_generate_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult)
}

/* Handle underlying C context. */
func (obj *MlDsa) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMlDsa() *MlDsa {
    ctx := C.vscf_ml_dsa_new()
    obj := &MlDsa {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MlDsa).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMlDsaWithCtx(ctx *C.vscf_ml_dsa_t) *MlDsa {
    obj := &MlDsa {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MlDsa).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMlDsaCopy(ctx *C.vscf_ml_dsa_t) *MlDsa {
    obj := &MlDsa {
        cCtx: C.vscf_ml_dsa_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MlDsa).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MlDsa) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MlDsa) delete() {
    C.vscf_ml_dsa_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *MlDsa) AlgId() AlgId {
    proxyResult := C.vscf_ml_dsa_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *MlDsa) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_ml_dsa_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult)
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *MlDsa) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := C.vscf_ml_dsa_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *MlDsa) GetCanImportPublicKey() bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *MlDsa) GetCanExportPublicKey() bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *MlDsa) GetCanImportPrivateKey() bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *MlDsa) GetCanExportPrivateKey() bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *MlDsa) GenerateEphemeralKey(key Key) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), &error)

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
func (obj *MlDsa) ImportPublicKey(rawKey *RawPublicKey) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *MlDsa) ExportPublicKey(publicKey PublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), &error)

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
func (obj *MlDsa) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(rawKey.Ctx())), &error)

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
func (obj *MlDsa) ExportPrivateKey(privateKey PrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ml_dsa_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return newRawPrivateKeyWithCtx(proxyResult), nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (obj *MlDsa) CanSign(privateKey PrivateKey) bool {
    proxyResult := C.vscf_ml_dsa_can_sign(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult)
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *MlDsa) SignatureLen(privateKey PrivateKey) uint {
    proxyResult := C.vscf_ml_dsa_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult)
}

/*
* Sign data digest with a given private key.
*/
func (obj *MlDsa) SignHash(privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := newBuffer(int(obj.SignatureLen(privateKey)))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.delete()
    digestData := helperWrapData (digest)

    proxyResult := C.vscf_ml_dsa_sign_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), C.vscf_alg_id_t(hashId), digestData, signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return signatureBuf.getData(), nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (obj *MlDsa) CanVerify(publicKey PublicKey) bool {
    proxyResult := C.vscf_ml_dsa_can_verify(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult)
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *MlDsa) VerifyHash(publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := C.vscf_ml_dsa_verify_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), C.vscf_alg_id_t(hashId), digestData, signatureData)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult)
}
