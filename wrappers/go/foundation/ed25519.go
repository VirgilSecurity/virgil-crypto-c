package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* This is implementation of Ed25519 elliptic curve algorithms.
*/
type Ed25519 struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IKeySigner
    IComputeSharedKey
    cCtx *C.vscf_ed25519_t /*ct10*/
}

func (this Ed25519) SetRandom (random IRandom) {
    C.vscf_ed25519_release_random(this.cCtx)
    C.vscf_ed25519_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (this Ed25519) SetEcies (ecies Ecies) {
    C.vscf_ed25519_release_ecies(this.cCtx)
    C.vscf_ed25519_use_ecies(this.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Ed25519) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_ed25519_setup_defaults(this.cCtx)

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
func (this Ed25519) GenerateKey () (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_generate_key(this.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this Ed25519) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewEd25519 () *Ed25519 {
    ctx := C.vscf_ed25519_new()
    return &Ed25519 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519WithCtx (ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    return &Ed25519 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEd25519Copy (ctx *C.vscf_ed25519_t /*ct10*/) *Ed25519 {
    return &Ed25519 {
        cCtx: C.vscf_ed25519_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Ed25519) close () {
    C.vscf_ed25519_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Ed25519) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ed25519_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Ed25519) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ed25519_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Ed25519) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_ed25519_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func Ed25519GetCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func Ed25519GetCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func Ed25519GetCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func Ed25519GetCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (this Ed25519) GenerateEphemeralKey (key IKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_generate_ephemeral_key(this.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

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
func (this Ed25519) ImportPublicKey (rawKey *RawPublicKey) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_import_public_key(this.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

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
func (this Ed25519) ExportPublicKey (publicKey IPublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_export_public_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

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
func (this Ed25519) ImportPrivateKey (rawKey *RawPrivateKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_import_private_key(this.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

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
func (this Ed25519) ExportPrivateKey (privateKey IPrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ed25519_export_private_key(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (this Ed25519) CanEncrypt (publicKey IPublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Ed25519) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_encrypted_len(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (this Ed25519) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ed25519_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (this Ed25519) CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Ed25519) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_decrypted_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (this Ed25519) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ed25519_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (this Ed25519) CanSign (privateKey IPrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_sign(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (this Ed25519) SignatureLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_signature_len(this.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (this Ed25519) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureCount := C.ulong(this.SignatureLen(privateKey.(IKey)) /* lg2 */)
    signatureMemory := make([]byte, int(C.vsc_buffer_ctx_size() + signatureCount))
    signatureBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&signatureMemory[0]))
    signatureData := signatureMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(signatureBuf)
    C.vsc_buffer_use(signatureBuf, (*C.byte)(unsafe.Pointer(&signatureData[0])), signatureCount)
    defer C.vsc_buffer_delete(signatureBuf)
    digestData := C.vsc_data((*C.uint8_t)(&digest[0]), C.size_t(len(digest)))

    proxyResult := /*pr4*/C.vscf_ed25519_sign_hash(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureData[0:C.vsc_buffer_len(signatureBuf)] /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (this Ed25519) CanVerify (publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_ed25519_can_verify(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (this Ed25519) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := C.vsc_data((*C.uint8_t)(&digest[0]), C.size_t(len(digest)))
    signatureData := C.vsc_data((*C.uint8_t)(&signature[0]), C.size_t(len(signature)))

    proxyResult := /*pr4*/C.vscf_ed25519_verify_hash(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    return bool(proxyResult) /* r9 */
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (this Ed25519) ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) ([]byte, error) {
    sharedKeyCount := C.ulong(this.SharedKeyLen(privateKey.(IKey)) /* lg2 */)
    sharedKeyMemory := make([]byte, int(C.vsc_buffer_ctx_size() + sharedKeyCount))
    sharedKeyBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&sharedKeyMemory[0]))
    sharedKeyData := sharedKeyMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(sharedKeyBuf)
    C.vsc_buffer_use(sharedKeyBuf, (*C.byte)(unsafe.Pointer(&sharedKeyData[0])), sharedKeyCount)
    defer C.vsc_buffer_delete(sharedKeyBuf)


    proxyResult := /*pr4*/C.vscf_ed25519_compute_shared_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (*C.vscf_impl_t)(privateKey.ctx()), sharedKeyBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return sharedKeyData[0:C.vsc_buffer_len(sharedKeyBuf)] /* r7 */, nil
}

/*
* Return number of bytes required to hold shared key.
* Expect Public Key or Private Key.
*/
func (this Ed25519) SharedKeyLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_ed25519_shared_key_len(this.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}
