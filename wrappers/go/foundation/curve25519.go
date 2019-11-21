package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* This is implementation of Curve25519 elliptic curve algorithms.
*/
type Curve25519 struct {
    cCtx *C.vscf_curve25519_t /*ct10*/
}

func (obj *Curve25519) SetRandom(random Random) {
    C.vscf_curve25519_release_random(obj.cCtx)
    C.vscf_curve25519_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *Curve25519) SetEcies(ecies Ecies) {
    C.vscf_curve25519_release_ecies(obj.cCtx)
    C.vscf_curve25519_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))

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

    runtime.KeepAlive(error)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Curve25519) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewCurve25519() *Curve25519 {
    ctx := C.vscf_curve25519_new()
    obj := &Curve25519 {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *Curve25519) {o.Delete()})
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
    //runtime.SetFinalizer(obj, func (o *Curve25519) {o.Delete()})
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
    //runtime.SetFinalizer(obj, func (o *Curve25519) {o.Delete()})
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
* Provide algorithm identificator.
*/
func (obj *Curve25519) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_curve25519_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Curve25519) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_curve25519_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Curve25519) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_curve25519_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

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

    proxyResult := /*pr4*/C.vscf_curve25519_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    runtime.KeepAlive(error)

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

    proxyResult := /*pr4*/C.vscf_curve25519_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    runtime.KeepAlive(error)

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

    proxyResult := /*pr4*/C.vscf_curve25519_export_public_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    runtime.KeepAlive(error)

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

    proxyResult := /*pr4*/C.vscf_curve25519_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawKey)

    runtime.KeepAlive(error)

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

    proxyResult := /*pr4*/C.vscf_curve25519_export_private_key(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    runtime.KeepAlive(error)

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (obj *Curve25519) CanEncrypt(publicKey PublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Curve25519) EncryptedLen(publicKey PublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Curve25519) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_curve25519_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf.ctx)

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
func (obj *Curve25519) CanDecrypt(privateKey PrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Curve25519) DecryptedLen(privateKey PrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Curve25519) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_curve25519_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf.ctx)

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


    proxyResult := /*pr4*/C.vscf_curve25519_compute_shared_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (*C.vscf_impl_t)(privateKey.ctx()), sharedKeyBuf.ctx)

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
func (obj *Curve25519) SharedKeyLen(key Key) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(key.ctx()))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return uint32(proxyResult) /* r9 */
}
