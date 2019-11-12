package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* This is implementation of Curve25519 elliptic curve algorithms.
*/
type Curve25519 struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IComputeSharedKey
    cCtx *C.vscf_curve25519_t /*ct10*/
}

func (obj *Curve25519) SetRandom (random IRandom) {
    C.vscf_curve25519_release_random(obj.cCtx)
    C.vscf_curve25519_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *Curve25519) SetEcies (ecies Ecies) {
    C.vscf_curve25519_release_ecies(obj.cCtx)
    C.vscf_curve25519_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Curve25519) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_curve25519_setup_defaults(obj.cCtx)

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
func (obj *Curve25519) GenerateKey () (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_generate_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Curve25519) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewCurve25519 () *Curve25519 {
    ctx := C.vscf_curve25519_new()
    return &Curve25519 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCurve25519WithCtx (ctx *C.vscf_curve25519_t /*ct10*/) *Curve25519 {
    return &Curve25519 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCurve25519Copy (ctx *C.vscf_curve25519_t /*ct10*/) *Curve25519 {
    return &Curve25519 {
        cCtx: C.vscf_curve25519_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *Curve25519) Delete () {
    C.vscf_curve25519_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Curve25519) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_curve25519_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Curve25519) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_curve25519_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Curve25519) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_curve25519_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func (obj *Curve25519) GetCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (obj *Curve25519) GetCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (obj *Curve25519) GetCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (obj *Curve25519) GetCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (obj *Curve25519) GenerateEphemeralKey (key IKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

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
func (obj *Curve25519) ImportPublicKey (rawKey *RawPublicKey) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

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
func (obj *Curve25519) ExportPublicKey (publicKey IPublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_export_public_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

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
func (obj *Curve25519) ImportPrivateKey (rawKey *RawPrivateKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

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
func (obj *Curve25519) ExportPrivateKey (privateKey IPrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_curve25519_export_private_key(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (obj *Curve25519) CanEncrypt (publicKey IPublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Curve25519) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Curve25519) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */))
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

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (obj *Curve25519) CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_curve25519_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Curve25519) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Curve25519) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */))
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

    return outBuf.getData() /* r7 */, nil
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (obj *Curve25519) ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := bufferNewBuffer(int(obj.SharedKeyLen(privateKey.(IKey)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.Delete()


    proxyResult := /*pr4*/C.vscf_curve25519_compute_shared_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (*C.vscf_impl_t)(privateKey.ctx()), sharedKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return sharedKeyBuf.getData() /* r7 */, nil
}

/*
* Return number of bytes required to hold shared key.
* Expect Public Key or Private Key.
*/
func (obj *Curve25519) SharedKeyLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_curve25519_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}
