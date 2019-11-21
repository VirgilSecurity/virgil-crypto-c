package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* This is implementation of Ed25519 elliptic curve algorithms.
*/
type Ed25519 struct {
    cCtx *C.vscf_ed25519_t /*ct10*/
}

func (obj *Ed25519) SetRandom(random Random) {
    C.vscf_ed25519_release_random(obj.cCtx)
    C.vscf_ed25519_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *Ed25519) SetEcies(ecies Ecies) {
    C.vscf_ed25519_release_ecies(obj.cCtx)
    C.vscf_ed25519_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
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

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *Ed25519) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewEd25519() *Ed25519 {
    ctx := C.vscf_ed25519_new()
    obj := &Ed25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519WithCtx(ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    obj := &Ed25519 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519Copy(ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    obj := &Ed25519 {
        cCtx: C.vscf_ed25519_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Ed25519) Delete() {
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
* Provide algorithm identificator.
*/
func (obj *Ed25519) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_ed25519_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Ed25519) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ed25519_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Ed25519) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_ed25519_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
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

    proxyResult := /*pr4*/C.vscf_ed25519_generate_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

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

    proxyResult := /*pr4*/C.vscf_ed25519_import_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

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

    proxyResult := /*pr4*/C.vscf_ed25519_export_public_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

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
func (obj *Ed25519) ImportPrivateKey(rawKey *RawPrivateKey) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_import_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

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

    proxyResult := /*pr4*/C.vscf_ed25519_export_private_key(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (obj *Ed25519) CanEncrypt(publicKey PublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Ed25519) EncryptedLen(publicKey PublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Ed25519) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ed25519_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf.ctx)

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
func (obj *Ed25519) CanDecrypt(privateKey PrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Ed25519) DecryptedLen(privateKey PrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Ed25519) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ed25519_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (obj *Ed25519) CanSign(privateKey PrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_sign(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (obj *Ed25519) SignatureLen(key Key) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_signature_len(obj.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (obj *Ed25519) SignHash(privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(obj.SignatureLen(privateKey.(Key)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.Delete()
    digestData := helperWrapData (digest)

    proxyResult := /*pr4*/C.vscf_ed25519_sign_hash(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureBuf.getData() /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (obj *Ed25519) CanVerify(publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_verify(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (obj *Ed25519) VerifyHash(publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := helperWrapData (digest)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_ed25519_verify_hash(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    return bool(proxyResult) /* r9 */
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (obj *Ed25519) ComputeSharedKey(publicKey PublicKey, privateKey PrivateKey) ([]byte, error) {
    sharedKeyBuf, sharedKeyBufErr := bufferNewBuffer(int(obj.SharedKeyLen(privateKey.(Key)) /* lg2 */))
    if sharedKeyBufErr != nil {
        return nil, sharedKeyBufErr
    }
    defer sharedKeyBuf.Delete()


    proxyResult := /*pr4*/C.vscf_ed25519_compute_shared_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (*C.vscf_impl_t)(privateKey.ctx()), sharedKeyBuf.ctx)

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
func (obj *Ed25519) SharedKeyLen(key Key) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_shared_key_len(obj.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}
